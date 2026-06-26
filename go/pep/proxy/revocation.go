package proxy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// revokeChannel is the kv.Bus channel session revocations are published on.
const revokeChannel = "pep_revoked"

// revoker tracks revoked session ids so the snapshot fast path can reject a still-valid snapshot immediately.
// memRevoker is single-instance; busRevoker keeps the set in sync across replicas over a kv.Bus.
type revoker interface {
	Revoke(sid string)
	IsRevoked(sid string) bool
}

// busRevoker is a memRevoker kept in sync across replicas over a kv.Bus: Revoke applies locally and publishes
// the sid so every other replica applies it too; a subscriber goroutine applies remote revocations.
type busRevoker struct {
	local *memRevoker
	bus   kv.Bus
}

func newBusRevoker(bus kv.Bus, ttl time.Duration) *busRevoker {
	r := &busRevoker{local: newMemRevoker(ttl), bus: bus}
	ch, err := bus.Subscribe(context.Background(), revokeChannel)
	if err != nil {
		slog.Error("revocation bus subscribe failed; revocations are local-only", "error", err)
		return r
	}
	go func() {
		for sid := range ch {
			r.local.Revoke(sid)
		}
	}()
	return r
}

func (r *busRevoker) Revoke(sid string) {
	r.local.Revoke(sid) // local immediately
	if err := r.bus.Publish(context.Background(), revokeChannel, sid); err != nil {
		slog.Warn("revocation publish failed; other replicas won't see it until the Stage 3 reconcile", "sid", sid, "error", err)
	}
}

func (r *busRevoker) IsRevoked(sid string) bool { return r.local.IsRevoked(sid) }

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
