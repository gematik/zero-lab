package nonce_test

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/redis/go-redis/v9"
)

func TestRedisNonceService(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	service, err := nonce.NewRedisNonceService(client, nonce.Options{ExpirySeconds: 2})
	if err != nil {
		t.Fatalf("creating redis nonce service: %v", err)
	}

	// A fresh nonce can be redeemed exactly once.
	n, err := service.Get()
	if err != nil {
		t.Fatalf("getting nonce: %v", err)
	}
	if err := service.Redeem(n); err != nil {
		t.Fatalf("redeeming nonce: %v", err)
	}
	if err := service.Redeem(n); err == nil {
		t.Fatal("expected error redeeming an already-redeemed nonce")
	}

	// An expired nonce can no longer be redeemed (advance miniredis' clock past the TTL).
	expiring, err := service.Get()
	if err != nil {
		t.Fatalf("getting nonce: %v", err)
	}
	mr.FastForward(3 * time.Second)
	if err := service.Redeem(expiring); err == nil {
		t.Fatal("expected error redeeming an expired nonce")
	}
}
