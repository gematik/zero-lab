// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
