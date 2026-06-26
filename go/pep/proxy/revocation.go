package proxy

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

const (
	// revokeChannel is the kv.Bus channel session revocations are published on.
	revokeChannel = "pep_revoked"
	// revokedPrefix namespaces the durable revoked-set keys in kv (one key per revoked sid).
	revokedPrefix = "pep:revoked:"
	// reconcileEvery is how often a replica re-reads the durable revoked-set, bounding the window in which a
	// dropped NOTIFY could let a revoked snapshot through.
	reconcileEvery = 30 * time.Second
)

// revoker tracks revoked session ids so the snapshot fast path can reject a still-valid snapshot immediately.
// memRevoker is single-instance; busRevoker keeps the set in sync across replicas over a kv.Bus.
type revoker interface {
	Revoke(sid string)
	IsRevoked(sid string) bool
}

// busRevoker keeps the local revoked-set in sync across replicas three ways: it publishes each revocation on
// a kv.Bus (instant fan-out), persists it to a durable kv set (so a fresh replica loads it on startup and a
// dropped NOTIFY is caught by the periodic reconcile), and applies remote revocations from the bus.
type busRevoker struct {
	local *memRevoker
	bus   kv.Bus
	store kv.Store
	ttl   time.Duration
}

func newBusRevoker(bus kv.Bus, store kv.Store, ttl time.Duration) *busRevoker {
	r := &busRevoker{local: newMemRevoker(ttl), bus: bus, store: store, ttl: ttl}
	r.reconcile() // startup: load the durable set so a fresh replica isn't blind to recent revocations
	if ch, err := bus.Subscribe(context.Background(), revokeChannel); err != nil {
		slog.Error("revocation bus subscribe failed; relying on the periodic reconcile", "error", err)
	} else {
		go func() {
			for sid := range ch {
				r.local.Revoke(sid)
			}
		}()
	}
	go r.reconcileLoop()
	return r
}

func (r *busRevoker) Revoke(sid string) {
	r.local.Revoke(sid) // local immediately
	// Durable backstop: persist so a fresh replica loads it on startup and a dropped NOTIFY is caught by
	// reconcile. TTL = the snapshot lifetime (self-cleaning — past it the snapshot is exp-rejected anyway).
	if err := r.store.Set(context.Background(), revokedPrefix+sid, []byte{'1'}, r.ttl); err != nil {
		slog.Warn("revocation backstop write failed", "sid", sid, "error", err)
	}
	if err := r.bus.Publish(context.Background(), revokeChannel, sid); err != nil {
		slog.Warn("revocation publish failed; other replicas catch it on reconcile", "sid", sid, "error", err)
	}
}

func (r *busRevoker) IsRevoked(sid string) bool { return r.local.IsRevoked(sid) }

// reconcile loads the durable revoked-set from the store into the local set.
func (r *busRevoker) reconcile() {
	keys, err := r.store.Keys(context.Background(), revokedPrefix)
	if err != nil {
		slog.Warn("revocation reconcile failed", "error", err)
		return
	}
	for _, k := range keys {
		r.local.Revoke(strings.TrimPrefix(k, revokedPrefix))
	}
}

func (r *busRevoker) reconcileLoop() {
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for range t.C {
		r.reconcile()
	}
}

// memRevoker is an in-memory revoked-session set with self-expiring entries (TTL = the snapshot lifetime —
// past that the snapshot is rejected by its own exp, so the entry is no longer needed).
type memRevoker struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]time.Time // sid -> entry expiry
}

func newMemRevoker(ttl time.Duration) *memRevoker {
	return &memRevoker{ttl: ttl, m: make(map[string]time.Time)}
}

func (r *memRevoker) Revoke(sid string) {
	if sid == "" {
		return
	}
	r.mu.Lock()
	r.m[sid] = time.Now().Add(r.ttl)
	r.mu.Unlock()
}

func (r *memRevoker) IsRevoked(sid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.m[sid]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(r.m, sid)
		return false
	}
	return true
}
