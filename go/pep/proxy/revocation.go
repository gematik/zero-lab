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

package proxy

import (
	"context"
	"sync"
	"time"
)

// Revocations are the session IDs ended before their time: at sign-out, and the ID a session had before it was
// rotated. The snapshot fast path admits a request without loading its session, so it asks here, and a
// revocation made at one replica must hold at every other (docs/stateless-session-validation.md).
type Revocations interface {
	// Revoke records sid as revoked until the given time, when every snapshot naming it has expired anyway.
	Revoke(ctx context.Context, sid string, until time.Time) error
	// Revoked reports whether sid is revoked. An error means it cannot tell, and the proxy denies.
	Revoked(ctx context.Context, sid string) (bool, error)
	// Follow applies the revocations made at other replicas: those made before the call by the time it returns,
	// and those made later until ctx ends. The host calls it before it serves; an error means it cannot follow.
	Follow(ctx context.Context) error
}

// MemoryRevocations are [Revocations] in the memory of this process, for a single replica. Entries leave when
// their time is up.
type MemoryRevocations struct {
	mu    sync.Mutex
	until map[string]time.Time
	now   func() time.Time
}

// NewMemoryRevocations returns empty revocations judged at now; nil means the system clock.
func NewMemoryRevocations(now func() time.Time) *MemoryRevocations {
	if now == nil {
		now = time.Now
	}
	return &MemoryRevocations{until: make(map[string]time.Time), now: now}
}

// Revoke implements [Revocations]. It never fails.
func (r *MemoryRevocations) Revoke(_ context.Context, sid string, until time.Time) error {
	if sid == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if until.After(r.until[sid]) {
		r.until[sid] = until
	}
	return nil
}

// Revoked implements [Revocations]. It never fails.
func (r *MemoryRevocations) Revoked(_ context.Context, sid string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.until[sid]
	if !ok {
		return false, nil
	}
	if r.now().After(until) {
		delete(r.until, sid)
		return false, nil
	}
	return true, nil
}

// Follow implements [Revocations]: there is no other replica to follow.
func (r *MemoryRevocations) Follow(context.Context) error { return nil }
