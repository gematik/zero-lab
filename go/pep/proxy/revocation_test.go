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
	store := kv.NewMemory() // shared durable store, as two replicas share one Postgres
	a := newBusRevoker(bus, store, time.Hour)
	b := newBusRevoker(bus, store, time.Hour)

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

func TestBusRevokerStartupLoad(t *testing.T) {
	// A revocation already in the durable set is loaded when a fresh replica starts.
	store := kv.NewMemory()
	if err := store.Set(context.Background(), revokedPrefix+"sid-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	if !r.IsRevoked("sid-old") {
		t.Error("startup did not load the durable revoked-set")
	}
}

func TestBusRevokerBackstopWrite(t *testing.T) {
	store := kv.NewMemory()
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	r.Revoke("sid-x")
	if _, found, _ := store.Get(context.Background(), revokedPrefix+"sid-x"); !found {
		t.Error("Revoke did not persist to the durable backstop")
	}
}

func TestBusRevokerReconcileCatchesMissed(t *testing.T) {
	// Simulate a dropped NOTIFY: the revocation lands in the durable set but not via the bus. Reconcile applies it.
	store := kv.NewMemory()
	r := newBusRevoker(kv.NewMemBus(), store, time.Hour)
	if err := store.Set(context.Background(), revokedPrefix+"sid-missed", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if r.IsRevoked("sid-missed") {
		t.Fatal("should not be revoked before reconcile")
	}
	r.reconcile()
	if !r.IsRevoked("sid-missed") {
		t.Error("reconcile did not pick up the durable entry (missed NOTIFY)")
	}
}
