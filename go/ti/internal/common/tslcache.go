package common

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/state"
)

const (
	tslCacheTTL  = 5 * time.Minute
	tslKeyPrefix = "pki:tsl:"
)

// NoCache, when set, makes LoadTSLCached bypass the local cache and always
// fetch from the network. Bound by the `ti pki --no-cache` persistent flag.
var NoCache bool

type tslCacheEntry struct {
	CachedAt time.Time `json:"cachedAt"`
	Hash     string    `json:"hash"`
	Raw      []byte    `json:"raw"`
}

func tslKey(url string) string { return tslKeyPrefix + url }

// LoadTSLCached returns a parsed TSL, using the unified state store as a
// 5-minute cache. On stale entries we run `IsTSLUpdateAvailable` so the 4MB
// XML only re-downloads when the upstream hash actually changed.
//
// If the state store is unavailable for any reason (permissions, disk full)
// we degrade to a direct LoadTSL so the CLI keeps working.
func LoadTSLCached(ctx context.Context, httpClient *http.Client, url string) (*gempki.TrustServiceStatusList, error) {
	if NoCache {
		return gempki.LoadTSL(ctx, httpClient, url)
	}

	st, err := LoadCLIState()
	if err != nil {
		slog.Warn("state cache unavailable, fetching TSL directly", "err", err)
		return gempki.LoadTSL(ctx, httpClient, url)
	}
	defer st.Close()

	key := tslKey(url)
	entry, hit, err := GetJSON[tslCacheEntry](st, key)
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
			if werr := SetJSON(st, key, entry, state.Expire(tslCacheTTL)); werr != nil {
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
	if werr := SetJSON(st, key, tslCacheEntry{
		CachedAt: time.Now(),
		Hash:     tsl.Hash,
		Raw:      tsl.Raw,
	}, state.Expire(tslCacheTTL)); werr != nil {
		slog.Warn("failed to write TSL cache", "err", werr)
	}
	return tsl, nil
}
