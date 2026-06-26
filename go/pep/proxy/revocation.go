package proxy

import (
	"sync"
	"time"
)

// revoker tracks revoked session ids so the snapshot fast path can reject a still-valid snapshot immediately.
// Stage 1 is single-instance (in-memory); Stage 2 swaps a kv pub/sub-backed implementation behind this
// interface so revocation propagates fleet-wide.
type revoker interface {
	Revoke(sid string)
	IsRevoked(sid string) bool
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
