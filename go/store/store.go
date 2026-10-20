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
	"context"
	"slices"
	"time"
)

// Stored is a record as the store hands it out.
type Stored struct {
	Name      Name
	Payload   []byte
	ExpiresAt time.Time
	// Kid is the kid it was sealed under; empty for a plain record.
	Kid string
}

// Meta is one indexed metadata value of a record.
type Meta struct {
	Field string
	Value []byte
}

// Store keeps records of registered namespaces in a [Backend], sealed by a [Sealer] where
// the namespace says so. Without a sealer, plain namespaces work and sealed ones are
// refused (STORE-023).
type Store struct {
	backend Backend
	sealer  Sealer
}

// New returns a store for namespaces, refused if the backend lacks a capability one of
// them requires (STORE-019). sealer may be nil.
func New(backend Backend, sealer Sealer, namespaces []Namespace) (*Store, error) {
	c := backend.Capabilities()
	for _, ns := range namespaces {
		r := ns.Requires
		switch {
		case r.AtomicTake && !c.AtomicTake:
			return nil, fail(CodeCapabilityMissing, "atomic take")
		case r.AtomicBatch && !c.AtomicBatch:
			return nil, fail(CodeCapabilityMissing, "atomic batch")
		case r.Indexed && !c.Indexed:
			return nil, fail(CodeCapabilityMissing, "indexed queries")
		case r.MultiProcess && !c.MultiProcess:
			return nil, fail(CodeCapabilityMissing, "multi-process access")
		}
	}
	return &Store{backend: backend, sealer: sealer}, nil
}

// Backend returns the backend.
func (s *Store) Backend() Backend { return s.backend }

func (s *Store) sealerFor(ns Namespace) (Sealer, error) {
	if ns.Kind == Plain {
		return nil, nil
	}
	if s.sealer == nil {
		return nil, ErrNoKeyring
	}
	return s.sealer, nil
}

func (s *Store) name(ns Namespace, id []byte) (Name, error) {
	sl, err := s.sealerFor(ns)
	switch {
	case err != nil:
		return Name{}, err
	case sl != nil:
		return sl.Name(ns.Name, id)
	}
	return PlainName(ns.Name, id)
}

func (s *Store) tags(ns Namespace, meta []Meta) ([]Tag, error) {
	sl, err := s.sealerFor(ns)
	if err != nil {
		return nil, err
	}
	tags := make([]Tag, 0, len(meta))
	for _, m := range meta {
		if !slices.Contains(ns.Fields, m.Field) {
			return nil, fail(CodeInvalidArgument, "field not indexed in this namespace")
		}
		var t Tag
		if sl != nil {
			t, err = sl.Tag(ns.Name, m.Field, m.Value)
		} else {
			t, err = PlainTag(ns.Name, m.Field, m.Value)
		}
		if err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, nil
}

func (s *Store) open(ns Namespace, name Name, r StoredRecord, now time.Time) (Stored, error) {
	sl, err := s.sealerFor(ns)
	if err != nil {
		return Stored{}, err
	}
	var o Opened
	if sl != nil {
		o, err = sl.Open(ns.Name, name, now, r.Value)
	} else {
		o, err = OpenPlain(now, r.Value)
	}
	if err != nil {
		return Stored{}, err
	}
	return Stored{Name: name, Payload: o.Payload, ExpiresAt: o.NotAfter, Kid: o.Kid}, nil
}

// Put stores payload under id with indexed metadata, replacing what was there
// (STORE-011, STORE-022). A zero expiresAt does not expire.
func (s *Store) Put(ctx context.Context, ns Namespace, id, payload []byte, meta []Meta, expiresAt, now time.Time) (Name, error) {
	// STORE-022: a namespace with a lifetime bounds every record.
	if ns.MaxTTL != 0 {
		if expiresAt.IsZero() {
			return Name{}, fail(CodeInvalidArgument, "record without expiry in a namespace with a lifetime")
		}
		if expiresAt.Unix() > now.Unix()+ns.MaxTTL {
			return Name{}, fail(CodeInvalidArgument, "expiry beyond the namespace's lifetime")
		}
	}
	name, err := s.name(ns, id)
	if err != nil {
		return Name{}, err
	}
	tags, err := s.tags(ns, meta)
	if err != nil {
		return Name{}, err
	}
	sl, _ := s.sealerFor(ns)
	var value []byte
	if sl != nil {
		value, err = sl.Seal(ns.Name, name, expiresAt, payload)
	} else {
		value, err = PlainRecord(expiresAt, payload)
	}
	if err != nil {
		return Name{}, err
	}
	return name, s.backend.Put(ctx, ns.Name, name, StoredRecord{Value: value, ExpiresAt: FromWire(wireTime(expiresAt)), Tags: tags})
}

// Get returns the live record under id (STORE-010, STORE-055).
func (s *Store) Get(ctx context.Context, ns Namespace, id []byte, now time.Time) (Stored, error) {
	name, err := s.name(ns, id)
	if err != nil {
		return Stored{}, err
	}
	r, err := s.backend.Get(ctx, ns.Name, name, now)
	if err != nil {
		return Stored{}, err
	}
	return s.open(ns, name, r, now)
}

// Take returns the live record under id and removes it: exactly one caller gets it
// (STORE-012).
func (s *Store) Take(ctx context.Context, ns Namespace, id []byte, now time.Time) (Stored, error) {
	if !s.backend.Capabilities().AtomicTake {
		return Stored{}, fail(CodeCapabilityMissing, "atomic take")
	}
	name, err := s.name(ns, id)
	if err != nil {
		return Stored{}, err
	}
	r, err := s.backend.Take(ctx, ns.Name, name, now)
	if err != nil {
		return Stored{}, err
	}
	return s.open(ns, name, r, now)
}

// Delete removes the record under id (STORE-013).
func (s *Store) Delete(ctx context.Context, ns Namespace, id []byte) error {
	name, err := s.name(ns, id)
	if err != nil {
		return err
	}
	return s.backend.Delete(ctx, ns.Name, name)
}

// Query returns live records whose metadata equals every filter, one page at a time
// (STORE-015, STORE-016). A record that does not open fails the page.
func (s *Store) Query(ctx context.Context, ns Namespace, filters []Meta, limit int, cursor *Name, now time.Time) ([]Stored, *Name, error) {
	tags, err := s.tags(ns, filters)
	if err != nil {
		return nil, nil, err
	}
	page, err := s.backend.Query(ctx, &Query{NS: ns.Name, Filters: tags, Limit: limit, Cursor: cursor, Now: now})
	if err != nil {
		return nil, nil, err
	}
	out := make([]Stored, 0, len(page.Records))
	for _, e := range page.Records {
		st, err := s.open(ns, e.Name, e.Record, now)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, st)
	}
	return out, page.Cursor, nil
}
