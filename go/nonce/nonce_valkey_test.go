package nonce_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/nonce"
	"github.com/valkey-io/valkey-go"
)

func TestValkeyNonceService(t *testing.T) {
	valkeyClient, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{"127.0.0.1:6379"},
	})
	if err != nil {
		t.Fatalf("creating Valkey client: %v", err)
	}

	service, err := nonce.NewValkeyNonceService(valkeyClient, nonce.Options{ExpirySeconds: 2})
	if err != nil {
		t.Fatalf("creating Valkey nonce service: %v", err)
	}

	nonceStr, err := service.Get()
	if err != nil {
		t.Fatalf("getting nonce: %v", err)
	}

	t.Logf("nonce: %s", nonceStr)

	err = service.Redeem(nonceStr)
	if err != nil {
		t.Fatalf("redeeming nonce: %v", err)
	}

	anotherNonceStr, err := service.Get()
	if err != nil {
		t.Fatalf("getting another nonce: %v", err)
	}

	t.Logf("another nonce: %s", anotherNonceStr)

	time.Sleep(3 * time.Second) // sleep for 3 seconds to let the nonce expire

	err = service.Redeem(anotherNonceStr)
	if err == nil {
		t.Fatalf("expected error redeeming expired nonce")
	}

	t.Logf("expected error: %v", err)

	yetAnotherNonceStr, err := service.Get()
	if err != nil {
		t.Fatalf("getting yet another nonce: %v", err)
	}

	t.Logf("yet another nonce: %s", yetAnotherNonceStr)

	err = service.Redeem(yetAnotherNonceStr)
	if err != nil {
		t.Fatalf("redeeming yet another nonce: %v", err)
	}

	// redeem again, expect error
	err = service.Redeem(yetAnotherNonceStr)
	if err == nil {
		t.Fatalf("expected error redeeming already redeemed nonce")
	}

	t.Logf("expected error: %v", err)

}
