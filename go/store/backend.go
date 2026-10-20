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
	"time"
)

// Capabilities are what a backend guarantees (STORE-018).
type Capabilities struct {
	// AtomicTake: take is atomic across processes and implementations (STORE-012).
	AtomicTake bool
	// AtomicBatch: batch is all or nothing (STORE-014).
	AtomicBatch bool
	// Indexed: query cost does not grow with records outside the result.
	Indexed bool
	// MultiProcess: several processes may use the same files.
	MultiProcess bool
}

// StoredRecord is a record as a backend keeps it.
type StoredRecord struct {
	// Value is the sealed or plain record (section F).
	Value []byte
	// ExpiresAt is the expiry; the zero time does not expire (STORE-002, STORE-053).
	ExpiresAt time.Time
	Tags      []Tag
}

// Check makes the checks every backend makes before it stores a record (STORE-011).
func (r *StoredRecord) Check() error {
	if len(r.Tags) > MaxTags {
		return fail(CodeLimitExceeded, "tags")
	}
	if err := checkWriteTime(r.ExpiresAt); err != nil {
		return err
	}
	for _, t := range r.Tags {
		if !ValidField(t.Field) {
			return fail(CodeInvalidArgument, "field")
		}
	}
	return nil
}

// Matches reports whether r carries every filter tag and its expiry is in the query's
// range; a record that does not expire counts as later than any time (STORE-015).
func (r *StoredRecord) Matches(q *Query) bool {
	e := wireTime(r.ExpiresAt)
	if e == 0 {
		if !q.To.IsZero() {
			return false
		}
	} else if (!q.From.IsZero() && e < wireTime(q.From)) || (!q.To.IsZero() && e >= wireTime(q.To)) {
		return false
	}
	for _, f := range q.Filters {
		if !slices.Contains(r.Tags, f) {
			return false
		}
	}
	return true
}

// Query selects live records of one namespace (STORE-015, STORE-016).
type Query struct {
	NS      string
	Filters []Tag
	// From is the lowest expiry, inclusive; To the highest, exclusive; zero is open.
	From, To time.Time
	// Limit is 1 to 1000.
	Limit int
	// Cursor: only names strictly greater; nil for the first page.
	Cursor *Name
	Now    time.Time
}

// Check validates the namespace, limit and filters.
func (q *Query) Check() error {
	if err := checkNamespace(q.NS); err != nil {
		return err
	}
	if q.Limit < 1 || q.Limit > 1000 {
		return fail(CodeInvalidArgument, "limit")
	}
	for _, f := range q.Filters {
		if !ValidField(f.Field) {
			return fail(CodeInvalidArgument, "field")
		}
	}
	return nil
}

// Entry is a named record of a page.
type Entry struct {
	Name   Name
	Record StoredRecord
}

// Page is one page of a query: records in ascending order of name, and a cursor exactly
// when the page is full (STORE-016).
type Page struct {
	Records []Entry
	Cursor  *Name
}

// NewPage makes a page of up to limit matches.
func NewPage(records []Entry, limit int) Page {
	p := Page{Records: records}
	if len(records) == limit && limit > 0 {
		c := records[len(records)-1].Name
		p.Cursor = &c
	}
	return p
}

// After reports whether name is after the cursor.
func (q *Query) After(name Name) bool {
	return q.Cursor == nil || bytes.Compare(name[:], q.Cursor[:]) > 0
}

// BatchOp is one operation of a batch: a put when Record is set, else a delete.
type BatchOp struct {
	NS     string
	Name   Name
	Record *StoredRecord
}

// Backend keeps records (section B).
type Backend interface {
	Capabilities() Capabilities
	// Get returns a live record or not_found (STORE-010).
	Get(ctx context.Context, ns string, name Name, now time.Time) (StoredRecord, error)
	// Put stores a record, replacing it and its tags (STORE-011).
	Put(ctx context.Context, ns string, name Name, r StoredRecord) error
	// Take returns a live record and removes it atomically (STORE-012).
	Take(ctx context.Context, ns string, name Name, now time.Time) (StoredRecord, error)
	// Delete removes a record; a missing one is no error (STORE-013).
	Delete(ctx context.Context, ns string, name Name) error
	// Batch applies all or nothing (STORE-014).
	Batch(ctx context.Context, ops []BatchOp) error
	// Query returns one page (STORE-015, STORE-016).
	Query(ctx context.Context, q *Query) (Page, error)
	// Cleanup removes up to limit expired records and says how many (STORE-017).
	Cleanup(ctx context.Context, now time.Time, limit int) (int, error)
}
