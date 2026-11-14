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

package dpop

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrReplaysFull is returned by [MemoryReplays.Seen] when it holds its maximum of unexpired
// entries. The verifier then refuses the proof rather than forget one it accepted.
var ErrReplaysFull = errors.New("dpop: replays full")

// MemoryReplays are [Replays] in the memory of one process: replicas of a server each keep
// their own, so a proof replayed at another replica is not detected there.
type MemoryReplays struct {
	mu      sync.Mutex
	limit   int
	clock   Clock
	entries map[string]time.Time
}

// NewMemoryReplays returns replays of at most limit unexpired entries, expiring them by clock
// (nil: the system clock).
func NewMemoryReplays(limit int, clock Clock) *MemoryReplays {
	return &MemoryReplays{limit: limit, clock: clockOrSystem(clock), entries: make(map[string]time.Time)}
}

// Seen records id until the given time and reports whether it was recorded and unexpired. It
// holds no I/O, so ctx is not consulted.
func (c *MemoryReplays) Seen(_ context.Context, id string, until time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	if expiry, ok := c.entries[id]; ok && now.Before(expiry) {
		return true, nil
	}
	if len(c.entries) >= c.limit {
		for k, expiry := range c.entries {
			if !now.Before(expiry) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.limit {
			return false, ErrReplaysFull
		}
	}
	c.entries[id] = until
	return false, nil
}
