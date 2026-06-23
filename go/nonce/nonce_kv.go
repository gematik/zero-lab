package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// kvNonceService issues single-use replay nonces backed by a kv.Store. Get stores a fresh nonce with a
// TTL; Redeem atomically Takes it, so a nonce is redeemable at most once even under concurrency (Take is
// the ACID primitive that the old Redis Exists+Del path lacked).
type kvNonceService struct {
	store kv.Store
	ttl   time.Duration
}

// NewKVService returns a nonce Service backed by store. ttl bounds how long an issued nonce stays
// redeemable.
func NewKVService(store kv.Store, ttl time.Duration) Service {
	return &kvNonceService{store: store, ttl: ttl}
}

const nonceBits = 256

func (s *kvNonceService) Get() (string, error) {
	b := make([]byte, nonceBits/8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	if err := s.store.Set(context.Background(), nonceKey(nonce), []byte(`1`), s.ttl); err != nil {
		return "", fmt.Errorf("storing nonce: %w", err)
	}
	return nonce, nil
}

func (s *kvNonceService) Redeem(nonce string) error {
	_, found, err := s.store.Take(context.Background(), nonceKey(nonce))
	if err != nil {
		return fmt.Errorf("redeeming nonce: %w", err)
	}
	if !found {
		return errors.New("nonce not found")
	}
	return nil
}

func nonceKey(nonce string) string { return "nonce:" + nonce }
