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

package titls

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultCacheSize is how many accepted verdicts a verifier keeps unless told otherwise.
const DefaultCacheSize = 1024

// verdictKey identifies one judgement: the presented chain, the host and the profile, and under ti the
// trust snapshot it was reached with (TLSV-050).
type verdictKey [sha256.Size]byte

func keyFor(profile string, generation uint64, host string, chain [][]byte) verdictKey {
	hash := sha256.New()
	field := func(data []byte) {
		_ = binary.Write(hash, binary.BigEndian, uint64(len(data)))
		hash.Write(data)
	}
	field([]byte(profile))
	_ = binary.Write(hash, binary.BigEndian, generation)
	field([]byte(strings.ToLower(host)))
	for _, der := range chain {
		field(der)
	}
	var key verdictKey
	hash.Sum(key[:0])
	return key
}

// verdictCache keeps accepted verdicts until they may no longer be reused, never more than max of them
// (TLSV-050). Refusals are never kept. Safe for concurrent use.
type verdictCache struct {
	mu      sync.Mutex
	max     int
	entries map[verdictKey]kept
}

// kept is an accepted verdict's end of reuse and its warnings, which a reuse reports as the first
// judgement did.
type kept struct {
	until    time.Time
	warnings []string
}

// newVerdictCache keeps up to size verdicts; zero means [DefaultCacheSize], a negative size keeps none.
func newVerdictCache(size int) *verdictCache {
	if size == 0 {
		size = DefaultCacheSize
	}
	return &verdictCache{max: max(size, 0), entries: map[verdictKey]kept{}}
}

// reusable is key's verdict as reused at now, with its warnings and the instant its reuse ends; false if
// there is none.
func (c *verdictCache) reusable(key verdictKey, now time.Time) (Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return Verdict{}, false
	}
	if !now.Before(entry.until) {
		delete(c.entries, key)
		return Verdict{}, false
	}
	return Verdict{Code: Valid, Detail: "reused", Warnings: slices.Clone(entry.warnings), ReusableUntil: entry.until}, true
}

// keep stores an accepted verdict reusable after now. When the cache is full, the verdicts no longer
// reusable go first, then the one that would end soonest.
func (c *verdictCache) keep(key verdictKey, verdict Verdict, now time.Time) {
	if c.max == 0 || !verdict.Valid() || !now.Before(verdict.ReusableUntil) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[key]; !present && len(c.entries) >= c.max {
		var soonest verdictKey
		var soonestUntil time.Time
		for k, entry := range c.entries {
			if !now.Before(entry.until) {
				delete(c.entries, k)
				continue
			}
			if soonestUntil.IsZero() || entry.until.Before(soonestUntil) {
				soonest, soonestUntil = k, entry.until
			}
		}
		if len(c.entries) >= c.max {
			delete(c.entries, soonest)
		}
	}
	c.entries[key] = kept{until: verdict.ReusableUntil, warnings: slices.Clone(verdict.Warnings)}
}

func (c *verdictCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
