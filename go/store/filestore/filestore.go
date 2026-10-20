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

// Package filestore is the files backend of spec/store (section I): one file per record,
// for small stores and for inspecting records by hand. It has atomic take and works
// across processes, but has neither atomic batch nor indexed queries.
package filestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/store"
)

// staleAfter is how old a leftover temporary or claimed file must be before cleanup
// removes it (STORE-083): older than any write or take in progress.
const staleAfter = time.Hour

// Backend keeps records below a root directory. Every file operation goes through an
// [os.Root], so a symbolic link inside the tree cannot lead an operation outside it.
type Backend struct {
	root *os.Root
	// now is the clock for removing stale leftovers, which is housekeeping, not a rule
	// on records; record expiry always uses the caller's time.
	now func() time.Time
}

// Open opens or creates the tree at root and checks its format level (STORE-086,
// STORE-100).
func Open(root string) (*Backend, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, store.BackendError("files root", err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, store.BackendError("files root", err)
	}
	b := &Backend{root: r, now: time.Now}
	raw, err := r.ReadFile("meta")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		m := store.FilesMeta{Level: store.MaxLevel, MinCompatible: store.MaxLevel}
		if err := b.writeAtomic(".", "meta", m.Encode()); err != nil {
			return nil, err
		}
		return b, nil
	case err != nil:
		return nil, store.BackendError("files meta", err)
	}
	m, err := store.ParseFilesMeta(raw)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := store.CheckLevel(store.MaxLevel, int(m.Level), int(m.MinCompatible)); err != nil {
		_ = r.Close()
		return nil, err
	}
	return b, nil
}

// Close releases the root directory.
func (b *Backend) Close() error { return b.root.Close() }

// Capabilities implements [store.Backend] (STORE-084).
func (*Backend) Capabilities() store.Capabilities {
	return store.Capabilities{AtomicTake: true, MultiProcess: true}
}

// path is relative to the root, as os.Root wants it.
func (b *Backend) path(ns string, name store.Name) (dir, file string) {
	p := filepath.Join("v1", filepath.FromSlash(store.RecordPath(ns, name)))
	return filepath.Dir(p), filepath.Base(p)
}

func randomSuffix() string {
	var r [8]byte
	_, _ = rand.Read(r[:])
	return hex.EncodeToString(r[:])
}

// writeAtomic writes to a new temporary file in dir, flushes it, renames it into place
// and flushes the directory (STORE-081, STORE-085).
func (b *Backend) writeAtomic(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, name+".tmp."+randomSuffix())
	f, err := b.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return store.BackendError("write", err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = b.root.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		_ = b.root.Remove(tmp)
		return store.BackendError("write", err)
	}
	return b.syncDir(dir)
}

func (b *Backend) syncDir(dir string) error {
	d, err := b.root.Open(dir)
	if err != nil {
		return store.BackendError("sync", err)
	}
	defer d.Close()
	// Some platforms cannot sync a directory; the rename is then as durable as they allow.
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return store.BackendError("sync", err)
	}
	return nil
}

func check(ns string) error {
	if !store.ValidNamespace(ns) {
		return &store.Error{Code: store.CodeInvalidArgument, What: "namespace"}
	}
	return nil
}

func (b *Backend) read(path string) (store.StoredRecord, error) {
	raw, err := b.root.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return store.StoredRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.StoredRecord{}, store.BackendError("read", err)
	}
	return store.ParseRecordFile(raw)
}

// Get implements [store.Backend].
func (b *Backend) Get(_ context.Context, ns string, name store.Name, now time.Time) (store.StoredRecord, error) {
	if err := check(ns); err != nil {
		return store.StoredRecord{}, err
	}
	dir, file := b.path(ns, name)
	r, err := b.read(filepath.Join(dir, file))
	if err != nil {
		return store.StoredRecord{}, err
	}
	if !store.Live(r.ExpiresAt, now) {
		return store.StoredRecord{}, store.ErrNotFound
	}
	return r, nil
}

// Put implements [store.Backend].
func (b *Backend) Put(_ context.Context, ns string, name store.Name, r store.StoredRecord) error {
	if err := check(ns); err != nil {
		return err
	}
	if err := r.Check(); err != nil {
		return err
	}
	dir, file := b.path(ns, name)
	if err := b.root.MkdirAll(dir, 0o700); err != nil {
		return store.BackendError("write", err)
	}
	return b.writeAtomic(dir, file, store.EncodeRecordFile(r))
}

// Take implements [store.Backend]: the process whose rename succeeds owns the record
// (STORE-082).
func (b *Backend) Take(_ context.Context, ns string, name store.Name, now time.Time) (store.StoredRecord, error) {
	if err := check(ns); err != nil {
		return store.StoredRecord{}, err
	}
	dir, file := b.path(ns, name)
	claim := filepath.Join(dir, strings.TrimSuffix(file, ".rec")+".take."+randomSuffix())
	if err := b.root.Rename(filepath.Join(dir, file), claim); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return store.StoredRecord{}, store.ErrNotFound
		}
		return store.StoredRecord{}, store.BackendError("take", err)
	}
	r, err := b.read(claim)
	_ = b.root.Remove(claim)
	if err != nil {
		return store.StoredRecord{}, err
	}
	if !store.Live(r.ExpiresAt, now) {
		return store.StoredRecord{}, store.ErrNotFound
	}
	return r, nil
}

// Delete implements [store.Backend].
func (b *Backend) Delete(_ context.Context, ns string, name store.Name) error {
	if err := check(ns); err != nil {
		return err
	}
	dir, file := b.path(ns, name)
	if err := b.root.Remove(filepath.Join(dir, file)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return store.BackendError("delete", err)
	}
	return nil
}

// Batch implements [store.Backend]; the files backend has no atomic batch (STORE-084).
func (*Backend) Batch(context.Context, []store.BatchOp) error {
	return &store.Error{Code: store.CodeCapabilityMissing, What: "atomic batch"}
}

// walk visits every record file of ns, or of every namespace if ns is empty, with paths
// relative to the root.
func (b *Backend) walk(ns string, visit func(path string, name store.Name) error) error {
	top := "v1"
	if ns != "" {
		top += "/" + ns
	}
	err := fs.WalkDir(b.root.FS(), top, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".rec") {
			return nil
		}
		raw, err := hex.DecodeString(strings.TrimSuffix(d.Name(), ".rec"))
		if err != nil || len(raw) != 32 {
			return nil
		}
		return visit(filepath.FromSlash(path), store.Name(raw))
	})
	if err != nil {
		return store.BackendError("walk", err)
	}
	return nil
}

// Query implements [store.Backend] by reading every file of the namespace (STORE-083).
func (b *Backend) Query(_ context.Context, q *store.Query) (store.Page, error) {
	if err := q.Check(); err != nil {
		return store.Page{}, err
	}
	var found []store.Entry
	err := b.walk(q.NS, func(path string, name store.Name) error {
		if !q.After(name) {
			return nil
		}
		r, err := b.read(path)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if store.Live(r.ExpiresAt, q.Now) && r.Matches(q) {
			found = append(found, store.Entry{Name: name, Record: r})
		}
		return nil
	})
	if err != nil {
		return store.Page{}, err
	}
	slices.SortFunc(found, func(a, c store.Entry) int { return bytes.Compare(a.Name[:], c.Name[:]) })
	if len(found) > q.Limit {
		found = found[:q.Limit]
	}
	return store.NewPage(found, q.Limit), nil
}

var errFull = errors.New("limit reached")

// Cleanup implements [store.Backend]; it also removes leftover temporary and claimed
// files older than an hour (STORE-083).
func (b *Backend) Cleanup(_ context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, &store.Error{Code: store.CodeInvalidArgument, What: "limit"}
	}
	removed := 0
	err := b.walk("", func(path string, _ store.Name) error {
		if removed == limit {
			return errFull
		}
		r, err := b.read(path)
		if err != nil {
			return nil
		}
		if !store.Live(r.ExpiresAt, now) {
			if err := b.root.Remove(path); err == nil {
				removed++
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errFull) {
		return removed, err
	}
	b.removeLeftovers()
	return removed, nil
}

func (b *Backend) removeLeftovers() {
	cutoff := b.now().Add(-staleAfter)
	_ = fs.WalkDir(b.root.FS(), "v1", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := d.Name()
		if !strings.Contains(n, ".tmp.") && !strings.Contains(n, ".take.") {
			return nil
		}
		if info, err := d.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = b.root.Remove(filepath.FromSlash(path))
		}
		return nil
	})
}
