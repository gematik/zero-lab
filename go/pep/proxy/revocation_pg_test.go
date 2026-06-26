package proxy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv/postgres"
)

// TestBusRevokerPostgres proves revocation crosses processes over real Postgres LISTEN/NOTIFY: two
// independently-connected busRevokers (two "replicas"), a Revoke on one must reach the other. Gated on
// PEP_PG_DSN.
func TestBusRevokerPostgres(t *testing.T) {
	dsn := os.Getenv("PEP_PG_DSN")
	if dsn == "" {
		t.Skip("PEP_PG_DSN not set — skipping Postgres LISTEN/NOTIFY integration test")
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	busA, err := postgres.OpenBus(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer busA.Close()
	busB, err := postgres.OpenBus(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer busB.Close()

	a := newBusRevoker(busA, store, time.Hour)
	b := newBusRevoker(busB, store, time.Hour)
	time.Sleep(300 * time.Millisecond) // let both listeners establish LISTEN before the first NOTIFY

	a.Revoke("sid-pg")
	deadline := time.Now().Add(5 * time.Second)
	for !b.IsRevoked("sid-pg") {
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate across processes via Postgres LISTEN/NOTIFY")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
