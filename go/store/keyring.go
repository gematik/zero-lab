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
	"encoding/binary"
	"encoding/hex"
	"io"
	"maps"
	"slices"
	"time"
)

// WrappedKey is one entry of a keyring file.
type WrappedKey struct {
	Kid       string
	Created   time.Time
	WrapperID string
	Wrapped   []byte
}

// KeyringFile is a keyring file as stored (STORE-060 to STORE-063); it holds no key in
// clear.
type KeyringFile struct {
	ProfileID  [16]byte
	CurrentKid string
	IndexKid   string
	Entries    []WrappedKey
}

var keyringMagic = []byte("ZLKR")

func validWrapperID(b []byte) bool {
	if len(b) < 1 || len(b) > 32 {
		return false
	}
	for _, c := range b {
		if !lower(c) && !digit(c) && c != '-' {
			return false
		}
	}
	return true
}

func (f *KeyringFile) entry(kid string) *WrappedKey {
	for i := range f.Entries {
		if f.Entries[i].Kid == kid {
			return &f.Entries[i]
		}
	}
	return nil
}

// ParseKeyringFile parses a keyring file (STORE-005, STORE-060, STORE-062).
func ParseKeyringFile(b []byte) (*KeyringFile, error) {
	r := &reader{b: b, what: "keyring"}
	if !bytes.Equal(r.take(4), keyringMagic) {
		return nil, r.malformed()
	}
	if v := r.u8(); r.err == nil && v != 1 {
		return nil, fail(CodeUnsupportedVersion, "keyring")
	}
	f := &KeyringFile{}
	copy(f.ProfileID[:], r.take(16))
	f.CurrentKid, f.IndexKid = string(r.lp()), string(r.lp())
	count := int(r.u16())
	if r.err != nil {
		return nil, r.err
	}
	if count < 1 || count > 256 || !ValidKid(f.CurrentKid) || !ValidKid(f.IndexKid) {
		return nil, r.malformed()
	}
	for range count {
		kid := string(r.lp())
		created := r.u64()
		id := r.lp()
		wrapped := r.lp()
		if r.err != nil {
			return nil, r.err
		}
		if !ValidKid(kid) || !validWrapperID(id) || f.entry(kid) != nil || created > MaxTime {
			return nil, r.malformed()
		}
		f.Entries = append(f.Entries, WrappedKey{Kid: kid, Created: FromWire(created), WrapperID: string(id), Wrapped: bytes.Clone(wrapped)})
	}
	if len(r.b) != 0 || f.entry(f.CurrentKid) == nil || f.entry(f.IndexKid) == nil {
		return nil, r.malformed()
	}
	return f, nil
}

// Encode returns the file's bytes (section G).
func (f *KeyringFile) Encode() []byte {
	out := append(bytes.Clone(keyringMagic), 1)
	out = append(out, f.ProfileID[:]...)
	out = appendLP(out, []byte(f.CurrentKid))
	out = appendLP(out, []byte(f.IndexKid))
	out = binary.BigEndian.AppendUint16(out, uint16(len(f.Entries)))
	for _, e := range f.Entries {
		out = appendLP(out, []byte(e.Kid))
		out = binary.BigEndian.AppendUint64(out, wireTime(e.Created))
		out = appendLP(out, []byte(e.WrapperID))
		out = appendLP(out, e.Wrapped)
	}
	return out
}

// KeyWrapper protects data keys in a keyring file (wrapper registry). It takes a context
// because a platform wrapper may wait for a device or a user.
type KeyWrapper interface {
	ID() string
	// Wrap binds dk to the profile and kid (STORE-063).
	Wrap(ctx context.Context, profileID [16]byte, kid string, dk []byte) ([]byte, error)
	// Unwrap fails with auth_failed if wrapped was altered or bound elsewhere (STORE-064).
	Unwrap(ctx context.Context, profileID [16]byte, kid string, wrapped []byte) ([]byte, error)
}

// KeyFileWrapper is the key-file wrapper: AES-256-GCM under a key-encryption key read
// from a file (STORE-094).
type KeyFileWrapper struct {
	kek  [32]byte
	rand io.Reader
}

// NewKeyFileWrapper takes the key from [ParseKEKFile]; rand supplies the wrapping nonces.
func NewKeyFileWrapper(kek [32]byte, rand io.Reader) *KeyFileWrapper {
	return &KeyFileWrapper{kek: kek, rand: rand}
}

// ID is "key-file".
func (*KeyFileWrapper) ID() string { return "key-file" }

func keyFileAAD(profileID [16]byte, kid string) []byte {
	return appendLP(appendLP(appendLP(nil, []byte("zl-keyring/1")), profileID[:]), []byte(kid))
}

// Wrap returns nonce ‖ AES-256-GCM(kek, nonce, dk, aad).
func (w *KeyFileWrapper) Wrap(_ context.Context, profileID [16]byte, kid string, dk []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(w.rand, nonce); err != nil {
		return nil, BackendError("random source", err)
	}
	return gcm(w.kek[:]).Seal(nonce, nonce, dk, keyFileAAD(profileID, kid)), nil
}

// Unwrap reverses Wrap.
func (w *KeyFileWrapper) Unwrap(_ context.Context, profileID [16]byte, kid string, wrapped []byte) ([]byte, error) {
	if len(wrapped) != 60 {
		return nil, fail(CodeMalformed, "wrapped key")
	}
	dk, err := gcm(w.kek[:]).Open(nil, wrapped[:12], wrapped[12:], keyFileAAD(profileID, kid))
	if err != nil {
		return nil, fail(CodeAuthFailed, "wrapped key")
	}
	return dk, nil
}

type keyringEntry struct {
	dk      []byte
	keys    DerivedKeys
	created time.Time
}

// Keyring is a profile's keyring with its data keys unwrapped: the software [Sealer].
type Keyring struct {
	profileID      [16]byte
	current, index string
	entries        map[string]*keyringEntry
	rand           io.Reader
}

func newEntry(dk []byte, created time.Time) (*keyringEntry, error) {
	keys, err := Derive(dk)
	if err != nil {
		return nil, err
	}
	return &keyringEntry{dk: dk, keys: keys, created: created}, nil
}

// OpenKeyring unwraps every data key of f (STORE-063, STORE-064). rand supplies nonces.
func OpenKeyring(ctx context.Context, f *KeyringFile, w KeyWrapper, rand io.Reader) (*Keyring, error) {
	k := &Keyring{profileID: f.ProfileID, current: f.CurrentKid, index: f.IndexKid, entries: map[string]*keyringEntry{}, rand: rand}
	for _, e := range f.Entries {
		if e.WrapperID != w.ID() {
			return nil, fail(CodeUnsupportedVersion, "wrapper")
		}
		dk, err := w.Unwrap(ctx, f.ProfileID, e.Kid, e.Wrapped)
		if err != nil {
			return nil, err
		}
		if k.entries[e.Kid], err = newEntry(dk, e.Created); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func randomBytes(rand io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, BackendError("random source", err)
	}
	return b, nil
}

// keys.md: identifiers come from the CSPRNG, never from time.
func randomKid(rand io.Reader) (string, error) {
	b, err := randomBytes(rand, 8)
	if err != nil {
		return "", err
	}
	return "k-" + hex.EncodeToString(b), nil
}

// CreateKeyring makes a keyring with a random profile id and one data key that is current
// and index key (STORE-061, STORE-095), and its file.
func CreateKeyring(ctx context.Context, w KeyWrapper, rand io.Reader, now time.Time) (*Keyring, *KeyringFile, error) {
	pid, err := randomBytes(rand, 16)
	if err != nil {
		return nil, nil, err
	}
	k := &Keyring{entries: map[string]*keyringEntry{}, rand: rand}
	copy(k.profileID[:], pid)
	f := &KeyringFile{ProfileID: k.profileID}
	if err := k.add(ctx, f, w, now); err != nil {
		return nil, nil, err
	}
	k.index, f.IndexKid = k.current, f.CurrentKid
	return k, f, nil
}

func (k *Keyring) add(ctx context.Context, f *KeyringFile, w KeyWrapper, now time.Time) error {
	if len(f.Entries) >= 256 {
		return fail(CodeLimitExceeded, "keyring")
	}
	kid, err := randomKid(k.rand)
	if err != nil {
		return err
	}
	dk, err := randomBytes(k.rand, 32)
	if err != nil {
		return err
	}
	wrapped, err := w.Wrap(ctx, k.profileID, kid, dk)
	if err != nil {
		return err
	}
	e, err := newEntry(dk, now)
	if err != nil {
		return err
	}
	f.Entries = append(f.Entries, WrappedKey{Kid: kid, Created: now, WrapperID: w.ID(), Wrapped: wrapped})
	f.CurrentKid = kid
	k.entries[kid], k.current = e, kid
	return nil
}

// Rotate adds a new data key and makes it current; records under older kids stay
// readable (STORE-043). It returns the new file.
func (k *Keyring) Rotate(ctx context.Context, f *KeyringFile, w KeyWrapper, now time.Time) (*KeyringFile, error) {
	next := *f
	next.Entries = append([]WrappedKey(nil), f.Entries...)
	if err := k.add(ctx, &next, w, now); err != nil {
		return nil, err
	}
	return &next, nil
}

// Rewrap returns the same keyring wrapped by w; records are not touched (STORE-127).
func (k *Keyring) Rewrap(ctx context.Context, w KeyWrapper) (*KeyringFile, error) {
	f := &KeyringFile{ProfileID: k.profileID, CurrentKid: k.current, IndexKid: k.index}
	for _, kid := range slices.Sorted(maps.Keys(k.entries)) {
		e := k.entries[kid]
		wrapped, err := w.Wrap(ctx, k.profileID, kid, e.dk)
		if err != nil {
			return nil, err
		}
		f.Entries = append(f.Entries, WrappedKey{Kid: kid, Created: e.created, WrapperID: w.ID(), Wrapped: wrapped})
	}
	return f, nil
}

// CurrentKid is the kid that seals new records.
func (k *Keyring) CurrentKid() string { return k.current }

// CurrentCreated is when the current kid was created, for STORE-058's yearly rotation.
func (k *Keyring) CurrentCreated() time.Time { return k.entries[k.current].created }

// Close overwrites the data keys.
func (k *Keyring) Close() {
	for _, e := range k.entries {
		clear(e.dk)
		e.keys.Clear()
	}
}

// ProfileID implements [Sealer].
func (k *Keyring) ProfileID() [16]byte { return k.profileID }

// Name implements [Sealer].
func (k *Keyring) Name(ns string, id []byte) (Name, error) {
	return k.entries[k.index].keys.Name(ns, id)
}

// Tag implements [Sealer].
func (k *Keyring) Tag(ns, field string, value []byte) (Tag, error) {
	return k.entries[k.index].keys.Tag(ns, field, value)
}

// Seal implements [Sealer].
func (k *Keyring) Seal(ns string, name Name, notAfter time.Time, payload []byte) ([]byte, error) {
	var nonce [12]byte
	if _, err := io.ReadFull(k.rand, nonce[:]); err != nil {
		return nil, BackendError("random source", err)
	}
	return SealRecord(k.entries[k.current].keys.ValueKey(), k.profileID, k.current, ns, name, notAfter, nonce, payload)
}

// Open implements [Sealer].
func (k *Keyring) Open(ns string, name Name, now time.Time, record []byte) (Opened, error) {
	return OpenSealed(func(kid string) *[32]byte {
		if e := k.entries[kid]; e != nil {
			return e.keys.ValueKey()
		}
		return nil
	}, k.profileID, ns, name, now, record)
}

// Sealer turns ids into names, metadata into tags and payloads into sealed records for
// one profile (sections D to F). [Keyring] keeps the keys in memory; other implementations
// may keep them in hardware.
type Sealer interface {
	ProfileID() [16]byte
	Name(ns string, id []byte) (Name, error)
	Tag(ns, field string, value []byte) (Tag, error)
	Seal(ns string, name Name, notAfter time.Time, payload []byte) ([]byte, error)
	Open(ns string, name Name, now time.Time, record []byte) (Opened, error)
}
