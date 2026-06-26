package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestMemBusPubSub(t *testing.T) {
	bus := kv.NewMemBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := bus.Subscribe(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(ctx, "c", "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got != "hello" {
			t.Errorf("got %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no message received")
	}
}

// TestBusRevokerPropagation models two replicas sharing one bus: a revoke on one must reach the other so
// logout/lockout is fleet-wide.
func TestBusRevokerPropagation(t *testing.T) {
	bus := kv.NewMemBus()
	a := newBusRevoker(bus, time.Hour)
	b := newBusRevoker(bus, time.Hour)

	a.Revoke("sid-1")
	if !a.IsRevoked("sid-1") {
		t.Fatal("revoke not applied on the originating replica")
	}
	// The other replica sees it asynchronously via the bus.
	deadline := time.Now().Add(2 * time.Second)
	for !b.IsRevoked("sid-1") {
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate to the other replica")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if b.IsRevoked("other") {
		t.Error("unrelated sid reported revoked")
	}
}
