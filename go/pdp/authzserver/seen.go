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

package authzserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
)

// seenClockSkew outlasts the difference between the replicas' clocks: a replica behind the one that recorded a
// proof or nonce still sees it as unexpired for that much longer, and the record must still be there.
const seenClockSkew = time.Minute

// kvSeen remembers identifiers under a key prefix of a kv.Store until they expire, atomically across the replicas
// on that store. It serves the DPoP replays (RFC 9449 Section 11.1) and the single use of client-assertion
// nonces. Records carry their own TTL and leave with kv.Reap. Nothing is written before a proof or nonce passed
// every other check, so an anonymous request costs no write.
type kvSeen struct {
	store  kv.Store
	prefix string
	// hashID keeps a client-chosen identifier, of any size, out of the key; a nonce's id is a hash already.
	hashID bool
}

var (
	_ dpop.Replays      = kvSeen{}
	_ nonce.Redemptions = kvSeen{}
)

// newKVReplays are the DPoP proofs accepted, under dpop:replay:<hex SHA-256 of the id>.
func newKVReplays(store kv.Store) kvSeen {
	return kvSeen{store: store, prefix: "dpop:replay:", hashID: true}
}

// newKVRedemptions are the client-assertion nonces redeemed, under nonce:<id>.
func newKVRedemptions(store kv.Store) kvSeen {
	return kvSeen{store: store, prefix: "nonce:"}
}

// Seen records id until the given time and reports whether it was recorded already. An error means the store
// could not tell, on which the caller refuses.
func (s kvSeen) Seen(ctx context.Context, id string, until time.Time) (bool, error) {
	if s.hashID {
		sum := sha256.Sum256([]byte(id))
		id = hex.EncodeToString(sum[:])
	}
	// max: a TTL of zero or below would mean a record that never expires.
	ttl := max(time.Until(until), 0) + seenClockSkew
	set, err := s.store.SetIfAbsent(ctx, s.prefix+id, []byte{1}, ttl)
	if err != nil {
		return false, fmt.Errorf("%s: %w", s.prefix, err)
	}
	return !set, nil
}
