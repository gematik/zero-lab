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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/oidf"
)

// documentsTimeout bounds each store call: the federation's callers hand in contexts that may carry no deadline,
// and a stalled store would otherwise hold a login.
const documentsTimeout = 5 * time.Second

// kvDocuments keeps oidf's federation documents under oidf:doc:<hex SHA-256 of the URL>, shared by the replicas
// on the store. oidf verifies every document it reads back again, so the store is trusted with availability only.
// Records carry their own TTL and leave with kv.Reap.
type kvDocuments struct {
	store kv.Store
}

var _ oidf.Documents = kvDocuments{}

func newKVDocuments(store kv.Store) kvDocuments { return kvDocuments{store: store} }

// documentKey keeps the URL, which comes from federation documents, out of the key.
func documentKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "oidf:doc:" + hex.EncodeToString(sum[:])
}

// Get returns the document kept for url.
func (d kvDocuments) Get(ctx context.Context, url string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, documentsTimeout)
	defer cancel()
	signed, found, err := d.store.Get(ctx, documentKey(url))
	if err != nil {
		return nil, false, fmt.Errorf("oidf documents: %w", err)
	}
	return signed, found, nil
}

// Keep stores the document until it expires. A document already expired is not stored: a TTL of zero or below
// would mean a record that never expires.
func (d kvDocuments) Keep(ctx context.Context, url string, signed []byte, until time.Time) error {
	ttl := time.Until(until)
	if ttl <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, documentsTimeout)
	defer cancel()
	if err := d.store.Set(ctx, documentKey(url), signed, ttl); err != nil {
		return fmt.Errorf("oidf documents: %w", err)
	}
	return nil
}
