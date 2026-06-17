package gempki

import (
	"context"
	"errors"
	"sync/atomic"
)

// TrustStoreHolder wraps a [TrustStore] behind an atomic pointer so callers
// can hot-swap the underlying roots — for instance, when a scheduled job
// refreshes the trust store after the gematik roots.json publishes a new
// rollover entry.
//
// Read-side access via [TrustStoreHolder.Current] is lock-free; writers
// reload atomically. Validators hold a *TrustStoreHolder rather than a
// *TrustStore so a running validator can pick up a refreshed store on the
// next call without any restart.
type TrustStoreHolder struct {
	ptr atomic.Pointer[TrustStore]
}

// NewTrustStoreHolder returns a holder seeded with initial. initial may be
// nil — Current returns nil until [TrustStoreHolder.Set] or
// [TrustStoreHolder.Reload] is called.
func NewTrustStoreHolder(initial *TrustStore) *TrustStoreHolder {
	h := &TrustStoreHolder{}
	if initial != nil {
		h.ptr.Store(initial)
	}
	return h
}

// Current returns the currently active TrustStore. The returned pointer is
// safe to retain — TrustStores are immutable.
func (h *TrustStoreHolder) Current() *TrustStore {
	if h == nil {
		return nil
	}
	return h.ptr.Load()
}

// Set installs ts as the active TrustStore. Passing nil is rejected so
// callers can't accidentally erase the trust store via a failed refresh path.
func (h *TrustStoreHolder) Set(ts *TrustStore) error {
	if h == nil {
		return errors.New("gempki: TrustStoreHolder is nil")
	}
	if ts == nil {
		return errors.New("gempki: refusing to install nil TrustStore — use a sentinel empty store if needed")
	}
	h.ptr.Store(ts)
	return nil
}

// Reload runs loader and, on success, installs the result as the active
// TrustStore. On failure the current store stays in place — Reload never
// leaves the holder empty.
//
// Reload is intended to be driven by a refresh ticker:
//
//	go func() {
//	    t := time.NewTicker(12 * time.Hour)
//	    for range t.C {
//	        if err := holder.Reload(ctx, loader); err != nil {
//	            slog.Warn("trust store refresh failed", "err", err)
//	        }
//	    }
//	}()
func (h *TrustStoreHolder) Reload(ctx context.Context, loader Loader) error {
	if h == nil {
		return errors.New("gempki: TrustStoreHolder is nil")
	}
	if loader == nil {
		return errors.New("gempki: Reload requires a non-nil Loader")
	}
	ts, err := loader.Load(ctx)
	if err != nil {
		return err
	}
	return h.Set(ts)
}
