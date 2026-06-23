package nonce_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
)

func TestKVService_GetRedeemSingleUse(t *testing.T) {
	svc := nonce.NewKVService(kv.NewMemory(), time.Minute)

	n, err := svc.Get()
	if err != nil || n == "" {
		t.Fatalf("get: %v %q", err, n)
	}
	if err := svc.Redeem(n); err != nil {
		t.Fatalf("first redeem should succeed: %v", err)
	}
	if err := svc.Redeem(n); err == nil {
		t.Fatal("second redeem should fail (single-use)")
	}
	if err := svc.Redeem("never-issued"); err == nil {
		t.Fatal("unknown nonce should fail")
	}
}

func TestKVService_Expiry(t *testing.T) {
	svc := nonce.NewKVService(kv.NewMemory(), 20*time.Millisecond)
	n, _ := svc.Get()
	time.Sleep(40 * time.Millisecond)
	if err := svc.Redeem(n); err == nil {
		t.Fatal("expired nonce should not redeem")
	}
}
