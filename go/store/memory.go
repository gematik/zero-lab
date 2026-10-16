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

package store

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"
)

// MemoryBackend keeps records in memory, lost with the process. One lock covers every
// operation, so take and batch are atomic within the process; there is no other process.
type MemoryBackend struct {
	mu      sync.Mutex
	records map[string]map[Name]StoredRecord
}

// NewMemoryBackend returns an empty backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{records: map[string]map[Name]StoredRecord{}}
}

// Capabilities implements [Backend].
func (*MemoryBackend) Capabilities() Capabilities {
	return Capabilities{AtomicTake: true, AtomicBatch: true}
}

func (m *MemoryBackend) put(ns string, name Name, r StoredRecord) {
	if m.records[ns] == nil {
		m.records[ns] = map[Name]StoredRecord{}
	}
	r.Value = bytes.Clone(r.Value)
	r.Tags = slices.Clone(r.Tags)
	m.records[ns][name] = r
}

// Get implements [Backend].
func (m *MemoryBackend) Get(_ context.Context, ns string, name Name, now time.Time) (StoredRecord, error) {
	if err := checkNamespace(ns); err != nil {
		return StoredRecord{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[ns][name]
	if !ok || !Live(r.ExpiresAt, now) {
		return StoredRecord{}, ErrNotFound
	}
	return r, nil
}

// Put implements [Backend].
func (m *MemoryBackend) Put(_ context.Context, ns string, name Name, r StoredRecord) error {
	if err := checkNamespace(ns); err != nil {
		return err
	}
	if err := r.Check(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.put(ns, name, r)
	return nil
}

// Take implements [Backend].
func (m *MemoryBackend) Take(_ context.Context, ns string, name Name, now time.Time) (StoredRecord, error) {
	if err := checkNamespace(ns); err != nil {
		return StoredRecord{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[ns][name]
	if !ok || !Live(r.ExpiresAt, now) {
		return StoredRecord{}, ErrNotFound
	}
	delete(m.records[ns], name)
	return r, nil
}

// Delete implements [Backend].
func (m *MemoryBackend) Delete(_ context.Context, ns string, name Name) error {
	if err := checkNamespace(ns); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records[ns], name)
	return nil
}

// Batch implements [Backend].
func (m *MemoryBackend) Batch(_ context.Context, ops []BatchOp) error {
	for _, op := range ops {
		if err := checkNamespace(op.NS); err != nil {
			return err
		}
		if op.Record != nil {
			if err := op.Record.Check(); err != nil {
				return err
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Record != nil {
			m.put(op.NS, op.Name, *op.Record)
		} else {
			delete(m.records[op.NS], op.Name)
		}
	}
	return nil
}

// Query implements [Backend].
func (m *MemoryBackend) Query(_ context.Context, q *Query) (Page, error) {
	if err := q.Check(); err != nil {
		return Page{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var found []Entry
	for name, r := range m.records[q.NS] {
		if q.After(name) && Live(r.ExpiresAt, q.Now) && r.Matches(q) {
			found = append(found, Entry{Name: name, Record: r})
		}
	}
	slices.SortFunc(found, func(a, b Entry) int { return bytes.Compare(a.Name[:], b.Name[:]) })
	if len(found) > q.Limit {
		found = found[:q.Limit]
	}
	return NewPage(found, q.Limit), nil
}

// Cleanup implements [Backend].
func (m *MemoryBackend) Cleanup(_ context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, fail(CodeInvalidArgument, "limit")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for _, recs := range m.records {
		for name, r := range recs {
			if removed == limit {
				return removed, nil
			}
			if !Live(r.ExpiresAt, now) {
				delete(recs, name)
				removed++
			}
		}
	}
	return removed, nil
}
