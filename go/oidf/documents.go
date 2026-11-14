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

package oidf

import (
	"context"
	"sync"
	"time"
)

// Documents keep the federation's signed documents (entity statements, signed JWK sets, the IdP list) between
// fetches, keyed by the URL they were fetched from. A document read back is verified again like a fetched one, with
// the same keys and at the same clock, so a store is trusted with availability only: a lost, stale or altered entry
// costs a fetch, never a decision (servers.md rules 3 and 12). A store shared by replicas spares each of them the
// federation's round trips.
type Documents interface {
	// Get returns the document kept for url; found is false when there is none.
	Get(ctx context.Context, url string) (signed []byte, found bool, err error)
	// Keep stores the document fetched from url until it expires; a later Keep for the same url replaces it.
	Keep(ctx context.Context, url string, signed []byte, until time.Time) error
}

// MemoryDocuments is an in-process [Documents] for tests and a single replica. It holds at most a fixed number of
// documents; when full, the one expiring soonest makes room.
type MemoryDocuments struct {
	mu      sync.Mutex
	max     int
	entries map[string]memoryDocument
	now     func() time.Time
}

type memoryDocument struct {
	signed []byte
	until  time.Time
}

// NewMemoryDocuments returns an empty store of at most capacity documents, at least one. now is the clock entries
// expire at; nil is the system clock.
func NewMemoryDocuments(capacity int, now func() time.Time) *MemoryDocuments {
	if now == nil {
		now = time.Now
	}
	return &MemoryDocuments{max: max(capacity, 1), entries: make(map[string]memoryDocument), now: now}
}

// Get implements [Documents]. An expired entry is not returned. It never fails.
func (d *MemoryDocuments) Get(_ context.Context, url string) ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.entries[url]
	if !ok {
		return nil, false, nil
	}
	if !d.now().Before(entry.until) {
		delete(d.entries, url)
		return nil, false, nil
	}
	return entry.signed, true, nil
}

// Keep implements [Documents]. A document that has already expired is not kept. It never fails.
func (d *MemoryDocuments) Keep(_ context.Context, url string, signed []byte, until time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.now().Before(until) {
		delete(d.entries, url)
		return nil
	}
	if _, replacing := d.entries[url]; !replacing && len(d.entries) >= d.max {
		d.evictSoonest()
	}
	d.entries[url] = memoryDocument{signed: append([]byte(nil), signed...), until: until}
	return nil
}

// evictSoonest drops the entry that would expire first, which is the one with the least use left. A linear scan is
// enough for the few hundred documents a federation has.
func (d *MemoryDocuments) evictSoonest() {
	var soonest string
	var until time.Time
	first := true
	for url, entry := range d.entries {
		if first || entry.until.Before(until) {
			soonest, until, first = url, entry.until, false
		}
	}
	delete(d.entries, soonest)
}
