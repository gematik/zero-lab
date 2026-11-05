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

package kv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// replayCacheSkew outlasts the difference between the replicas' clocks: a replica behind the one that recorded
// a proof still accepts its iat for that much longer, and the record must still be there.
const replayCacheSkew = time.Minute

// replayCacheTimeout bounds the store call on the request path; Seen has no context to inherit one from.
const replayCacheTimeout = 5 * time.Second

// ReplayCache has the shape of dpop.ReplayCache, on a Store, so a proof replayed at another replica is refused
// (RFC 9449 Section 11.1). The kv module stays free of dpop: the interface is met, not imported.
type ReplayCache struct {
	store Store
}

// NewReplayCache returns a cache on store. Records carry their own TTL and leave with [Reap].
func NewReplayCache(store Store) *ReplayCache {
	return &ReplayCache{store: store}
}

// Seen records id until the given time and reports whether it was recorded already. An error means the store
// could not tell, on which a caller must refuse.
func (c *ReplayCache) Seen(id string, until time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), replayCacheTimeout)
	defer cancel()
	sum := sha256.Sum256([]byte(id))
	// max: a TTL of zero or below would mean a record that never expires.
	ttl := max(time.Until(until), 0) + replayCacheSkew
	set, err := c.store.SetIfAbsent(ctx, "dpop:replay:"+hex.EncodeToString(sum[:]), []byte{1}, ttl)
	if err != nil {
		return false, fmt.Errorf("kv: replay cache: %w", err)
	}
	return !set, nil
}
