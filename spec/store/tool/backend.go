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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// capabilities of STORE-018, per backend (STORE-078, STORE-084).
type capabilities struct {
	AtomicTake   bool `json:"atomic_take"`
	AtomicBatch  bool `json:"atomic_batch"`
	Indexed      bool `json:"indexed"`
	MultiProcess bool `json:"multi_process"`
}

var backendCapabilities = map[string]capabilities{
	"sqlite": {AtomicTake: true, AtomicBatch: true, Indexed: true, MultiProcess: true},
	"files":  {AtomicTake: true, MultiProcess: true},
}

type memRecord struct {
	value     []byte
	expiresAt uint64
	tags      []fileTag
}

// memBackend is the reference for the operation scenarios: section B on a map, with the
// capabilities of the backend the scenario targets.
type memBackend struct {
	caps    capabilities
	records map[string]map[string]memRecord
}

func newMemBackend(caps capabilities) *memBackend {
	return &memBackend{caps: caps, records: map[string]map[string]memRecord{}}
}

// STORE-003
func live(expiresAt, now uint64) bool { return expiresAt == 0 || expiresAt > now }

func validRecordKey(ns string, name []byte) error {
	if !nsSyntax.MatchString(ns) || len(name) != 32 {
		return codeInvalidArgument
	}
	return nil
}

func validPut(ns string, name []byte, tags []fileTag) error {
	if err := validRecordKey(ns, name); err != nil {
		return err
	}
	if len(tags) > maxTags {
		return codeLimitExceeded
	}
	for _, t := range tags {
		if !fieldSyntax.MatchString(t.field) || len(t.tag) != 32 {
			return codeInvalidArgument
		}
	}
	return nil
}

// STORE-011
func (m *memBackend) put(ns string, name, value []byte, expiresAt uint64, tags []fileTag) error {
	if err := validPut(ns, name, tags); err != nil {
		return err
	}
	if m.records[ns] == nil {
		m.records[ns] = map[string]memRecord{}
	}
	m.records[ns][string(name)] = memRecord{value: value, expiresAt: expiresAt, tags: tags}
	return nil
}

// STORE-010
func (m *memBackend) get(ns string, name []byte, now uint64) (memRecord, error) {
	if err := validRecordKey(ns, name); err != nil {
		return memRecord{}, err
	}
	r, ok := m.records[ns][string(name)]
	if !ok || !live(r.expiresAt, now) {
		return memRecord{}, codeNotFound
	}
	return r, nil
}

// STORE-012
func (m *memBackend) take(ns string, name []byte, now uint64) (memRecord, error) {
	if !m.caps.AtomicTake {
		return memRecord{}, codeCapabilityMissing
	}
	r, err := m.get(ns, name, now)
	if err != nil {
		return memRecord{}, err
	}
	delete(m.records[ns], string(name))
	return r, nil
}

// STORE-013
func (m *memBackend) delete(ns string, name []byte) error {
	if err := validRecordKey(ns, name); err != nil {
		return err
	}
	delete(m.records[ns], string(name))
	return nil
}

type batchOp struct {
	op        string
	ns        string
	name      []byte
	value     []byte
	expiresAt uint64
	tags      []fileTag
}

// STORE-014: validate everything, then apply everything.
func (m *memBackend) batch(ops []batchOp) error {
	if !m.caps.AtomicBatch {
		return codeCapabilityMissing
	}
	for _, o := range ops {
		var err error
		switch o.op {
		case "put":
			err = validPut(o.ns, o.name, o.tags)
		case "delete":
			err = validRecordKey(o.ns, o.name)
		default:
			err = codeInvalidArgument
		}
		if err != nil {
			return err
		}
	}
	for _, o := range ops {
		if o.op == "put" {
			_ = m.put(o.ns, o.name, o.value, o.expiresAt, o.tags)
		} else {
			_ = m.delete(o.ns, o.name)
		}
	}
	return nil
}

type queryArgs struct {
	ns       string
	filters  []fileTag
	from, to *uint64
	limit    int
	cursor   []byte
	now      uint64
}

// inRange places a record without expiry after any time (STORE-015).
func inRange(expiresAt uint64, from, to *uint64) bool {
	if expiresAt == 0 {
		return to == nil
	}
	return (from == nil || expiresAt >= *from) && (to == nil || expiresAt < *to)
}

func hasTag(tags []fileTag, f fileTag) bool {
	for _, t := range tags {
		if t.field == f.field && bytes.Equal(t.tag, f.tag) {
			return true
		}
	}
	return false
}

// STORE-015, STORE-016. The cursor is returned when exactly limit records were returned.
func (m *memBackend) query(q queryArgs) ([][]byte, []byte, error) {
	if !nsSyntax.MatchString(q.ns) || q.limit < 1 || q.limit > 1000 {
		return nil, nil, codeInvalidArgument
	}
	if q.cursor != nil && len(q.cursor) != 32 {
		return nil, nil, codeInvalidArgument
	}
	for _, f := range q.filters {
		if !fieldSyntax.MatchString(f.field) || len(f.tag) != 32 {
			return nil, nil, codeInvalidArgument
		}
	}
	var names [][]byte
	for k, r := range m.records[q.ns] {
		name := []byte(k)
		if !live(r.expiresAt, q.now) || !inRange(r.expiresAt, q.from, q.to) {
			continue
		}
		if q.cursor != nil && bytes.Compare(name, q.cursor) <= 0 {
			continue
		}
		match := true
		for _, f := range q.filters {
			if !hasTag(r.tags, f) {
				match = false
				break
			}
		}
		if match {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return bytes.Compare(names[i], names[j]) < 0 })
	if len(names) > q.limit {
		names = names[:q.limit]
	}
	var cursor []byte
	if len(names) == q.limit {
		cursor = names[len(names)-1]
	}
	return names, cursor, nil
}

// STORE-017
func (m *memBackend) cleanup(now uint64, limit int) (int, error) {
	if limit < 1 {
		return 0, codeInvalidArgument
	}
	removed := 0
	for _, recs := range m.records {
		for k, r := range recs {
			if removed == limit {
				return removed, nil
			}
			if !live(r.expiresAt, now) {
				delete(recs, k)
				removed++
			}
		}
	}
	return removed, nil
}

// fillName and fillValue define the records of a scenario's fill step.
func fillName(seed []byte, i int) []byte {
	return sha(seed, binary.BigEndian.AppendUint32(nil, uint32(i)))
}

func fillValue(i int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(i)) }

// scan pages through a namespace and digests the names in order, so that a corpus of
// many records compares as two numbers.
func (m *memBackend) scan(ns string, limit int, now uint64) (int, []byte, error) {
	h := sha256.New()
	count := 0
	var cursor []byte
	for {
		names, next, err := m.query(queryArgs{ns: ns, limit: limit, cursor: cursor, now: now})
		if err != nil {
			return 0, nil, err
		}
		for _, n := range names {
			h.Write(n)
		}
		count += len(names)
		if next == nil {
			return count, h.Sum(nil), nil
		}
		cursor = next
	}
}
