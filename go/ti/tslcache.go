package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
	bolt "go.etcd.io/bbolt"
)

const tslCacheTTL = 5 * time.Minute

var tslBucket = []byte("tsl")

type tslCacheEntry struct {
	CachedAt time.Time `json:"cachedAt"`
	Hash     string    `json:"hash"`
	Raw      []byte    `json:"raw"`
}

// loadTSLCached returns a parsed TSL, using a local bbolt cache.
// Cache entries younger than 5 minutes are re-parsed from stored bytes.
// Stale entries trigger an IsTSLUpdateAvailable check; the full XML is
// only re-downloaded when the server hash differs.
// If bbolt is unavailable, falls back to a direct LoadTSL call.
func loadTSLCached(ctx context.Context, httpClient *http.Client, url string) (*gempki.TrustServiceStatusList, error) {
	if noCacheFlag {
		return gempki.LoadTSL(ctx, httpClient, url)
	}

	db, err := openDB()
	if err != nil {
		slog.Warn("TSL cache unavailable, fetching directly", "err", err)
		return gempki.LoadTSL(ctx, httpClient, url)
	}
	defer db.Close()

	entry, _ := readTSLCache(db, url)

	if entry != nil && time.Since(entry.CachedAt) < tslCacheTTL {
		slog.Debug("TSL cache hit", "url", url, "age", time.Since(entry.CachedAt).Round(time.Second))
		return gempki.ParseTSL(bytes.NewReader(entry.Raw), url)
	}

	if entry != nil {
		updated, err := gempki.IsTSLUpdateAvailable(ctx, httpClient, url, entry.Hash)
		if err == nil && !updated {
			slog.Debug("TSL unchanged, refreshing cache timestamp", "url", url)
			entry.CachedAt = time.Now()
			if werr := writeTSLCache(db, url, entry); werr != nil {
				slog.Warn("failed to refresh TSL cache timestamp", "err", werr)
			}
			return gempki.ParseTSL(bytes.NewReader(entry.Raw), url)
		}
		slog.Debug("TSL update available", "url", url)
	}

	tsl, err := gempki.LoadTSL(ctx, httpClient, url)
	if err != nil {
		return nil, err
	}
	if werr := writeTSLCache(db, url, &tslCacheEntry{
		CachedAt: time.Now(),
		Hash:     tsl.Hash,
		Raw:      tsl.Raw,
	}); werr != nil {
		slog.Warn("failed to write TSL cache", "err", werr)
	}
	return tsl, nil
}

func newPKIClearCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear-cache",
		Short: "Delete all locally cached PKI data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			return db.Update(func(tx *bolt.Tx) error {
				if tx.Bucket(tslBucket) == nil {
					fmt.Println("Cache is already empty.")
					return nil
				}
				if err := tx.DeleteBucket(tslBucket); err != nil {
					return err
				}
				fmt.Println("Cache cleared.")
				return nil
			})
		},
	}
}

func readTSLCache(db *bolt.DB, url string) (*tslCacheEntry, error) {
	var entry tslCacheEntry
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(tslBucket)
		if b == nil {
			return fmt.Errorf("bucket not found")
		}
		data := b.Get([]byte(url))
		if data == nil {
			return fmt.Errorf("not cached")
		}
		return json.Unmarshal(data, &entry)
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func writeTSLCache(db *bolt.DB, url string, entry *tslCacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(tslBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(url), data)
	})
}
