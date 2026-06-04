package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/state"
	"github.com/spf13/cobra"
)

const (
	tslCacheTTL  = 5 * time.Minute
	tslKeyPrefix = "pki:tsl:"
)

type tslCacheEntry struct {
	CachedAt time.Time `json:"cachedAt"`
	Hash     string    `json:"hash"`
	Raw      []byte    `json:"raw"`
}

func tslKey(url string) string { return tslKeyPrefix + url }

// loadTSLCached returns a parsed TSL, using the unified state store as a
// 5-minute cache. On stale entries we run `IsTSLUpdateAvailable` so the 4MB
// XML only re-downloads when the upstream hash actually changed.
//
// If the state store is unavailable for any reason (permissions, disk full)
// we degrade to a direct LoadTSL so the CLI keeps working.
func loadTSLCached(ctx context.Context, httpClient *http.Client, url string) (*gempki.TrustServiceStatusList, error) {
	if noCacheFlag {
		return gempki.LoadTSL(ctx, httpClient, url)
	}

	st, err := loadCLIState()
	if err != nil {
		slog.Warn("state cache unavailable, fetching TSL directly", "err", err)
		return gempki.LoadTSL(ctx, httpClient, url)
	}
	defer st.Close()

	key := tslKey(url)
	entry, hit, err := getJSON[tslCacheEntry](st, key)
	if err != nil {
		slog.Warn("TSL cache read failed, fetching directly", "err", err)
		return gempki.LoadTSL(ctx, httpClient, url)
	}

	if hit && time.Since(entry.CachedAt) < tslCacheTTL {
		slog.Debug("TSL cache hit", "url", url, "age", time.Since(entry.CachedAt).Round(time.Second))
		return gempki.ParseTSL(bytes.NewReader(entry.Raw), url)
	}

	if hit {
		updated, err := gempki.IsTSLUpdateAvailable(ctx, httpClient, url, entry.Hash)
		if err == nil && !updated {
			slog.Debug("TSL unchanged, refreshing cache timestamp", "url", url)
			entry.CachedAt = time.Now()
			if werr := setJSON(st, key, entry, state.Expire(tslCacheTTL)); werr != nil {
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
	if werr := setJSON(st, key, tslCacheEntry{
		CachedAt: time.Now(),
		Hash:     tsl.Hash,
		Raw:      tsl.Raw,
	}, state.Expire(tslCacheTTL)); werr != nil {
		slog.Warn("failed to write TSL cache", "err", werr)
	}
	return tsl, nil
}

// newPKIClearCacheCmd wipes all `pki:`-prefixed entries from the unified state
// store. Cosmetic-only difference from `ti epa cache clear pki:…` per key —
// kept as a distinct command so users with muscle memory still find it.
func newPKIClearCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear-cache",
		Short: "Delete all locally cached PKI data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			keys, err := st.Keys("pki:")
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				fmt.Println("Cache is already empty.")
				return nil
			}
			for _, k := range keys {
				if err := st.Delete(k); err != nil {
					return fmt.Errorf("deleting %q: %w", k, err)
				}
			}
			fmt.Printf("Cache cleared (%d entries: %s).\n", len(keys), strings.Join(keys, ", "))
			return nil
		},
	}
}
