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

package kv

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	keychainIVSize  = 12
	keychainTagSize = 16
	// keychainUnwrapTimeout bounds one call to the key service, at start and at a reload.
	keychainUnwrapTimeout = 10 * time.Second
)

// Unwrapper is the key service that holds the key-encryption keys of a [Keychain]: an HSM, a KMS, or for
// development a key in a file ([LocalKEK]). The key-encryption key never leaves it; what it hands out is the
// key material of one entry.
type Unwrapper interface {
	// Unwrap decrypts what was encrypted under the key kekID with AES-256-GCM, and fails if the associated
	// data is not the one it was encrypted with. The plaintext is the caller's, to clear.
	Unwrap(ctx context.Context, kekID string, iv, ciphertext, tag, associatedData []byte) ([]byte, error)
}

// NameKey is the key of one keychain entry for deriving names: pseudonyms of what must not stand in a database
// key in the clear.
type NameKey struct {
	// ID is the ID of the entry.
	ID  string
	Key []byte
	// Since is from when the entry is in force by its own word.
	Since time.Time
}

// Keychain is a key ring of versioned entries whose keys are wrapped: each entry holds a key that seals and
// a key for names, encrypted together under a key-encryption key that an [Unwrapper] holds (envelope
// encryption, server rule 19). The file can lie beside the data: without the key service it opens nothing.
//
// The file is the keychain of the notification service of ZETA Guard, so that one generator serves both: a
// JSON array of entries
//
//	{"id": "<family>-v<N>", "kekId": "…", "activeFrom": "<RFC 3339>", "keys": "<base64 of iv, ciphertext, tag>"}
//
// with an optional "emergency": true. The ciphertext is 64 bytes, the sealing key and the name key; the
// associated data is the entry's ID, followed by "/emergency" for such an entry, so that neither can be
// changed without the unwrapping failing.
//
// The entry with the highest version whose activeFrom has passed is current: it seals, and its name key
// comes first. Every entry opens. Rotating (server rule 22): add the new entry with an activeFrom by which
// every pod holds it; move what has to outlive the old entry to the new one; then drop the old entry. A
// keychain from [LoadKeychain] follows its file, so nothing needs a restart.
type Keychain struct {
	mu      sync.RWMutex
	entries []keychainEntry // by version, rising

	unwrap     Unwrapper
	agreed     func(id string) bool
	path       string
	now        func() time.Time
	checkedAt  atomic.Int64
	fileMod    time.Time
	fileSize   int64
	reloadLock sync.Mutex
}

type keychainEntry struct {
	id         string
	version    int
	activeFrom time.Time
	wrapped    string
	seal, name []byte
}

// keychainFileEntry is one entry as the file has it.
type keychainFileEntry struct {
	ID         string    `json:"id"`
	KEKID      string    `json:"kekId"`
	ActiveFrom time.Time `json:"activeFrom"`
	Emergency  bool      `json:"emergency,omitempty"`
	Keys       string    `json:"keys"`
}

var keychainEntryID = regexp.MustCompile(`^[A-Za-z0-9._-]*-v([0-9]{1,9})$`)

// KeychainOption adjusts a [Keychain].
type KeychainOption func(*Keychain)

// WithKeychainClock sets the clock that says which entry is in force and paces the looks at the file; the
// default is time.Now.
func WithKeychainClock(now func() time.Time) KeychainOption {
	return func(k *Keychain) { k.now = now }
}

// WithKeychainAgreement makes an entry wait for the other replicas: its time having come, it is in force
// only once agreed reports true for its ID, which the caller answers from what the replicas tell each other
// they are ready for ([Keychain.Ready]). Without it a replica that has not got the new entry yet, or whose
// clock is behind, goes on with the old one while the others have moved on, and what it writes is not where
// they look (server rule 22). While no entry is agreed there is no current key.
func WithKeychainAgreement(agreed func(id string) bool) KeychainOption {
	return func(k *Keychain) { k.agreed = agreed }
}

// ParseKeychain unwraps the entries of a keychain file. The keychain does not follow a file.
func ParseKeychain(ctx context.Context, data []byte, unwrap Unwrapper, opts ...KeychainOption) (*Keychain, error) {
	entries, err := parseKeychain(ctx, data, unwrap, nil)
	if err != nil {
		return nil, err
	}
	k := &Keychain{entries: entries, unwrap: unwrap, now: time.Now}
	for _, opt := range opts {
		opt(k)
	}
	return k, nil
}

// LoadKeychain reads a keychain from the file at path, unwraps its entries, and keeps following the file as
// [LoadKeyring] does: a changed file is read again within 30 s, only its new entries are unwrapped, and a
// reload that fails keeps the keys in force and logs at error level until it succeeds.
func LoadKeychain(ctx context.Context, path string, unwrap Unwrapper, opts ...KeychainOption) (*Keychain, error) {
	info, data, err := readKeyringFile(path)
	if err != nil {
		return nil, err
	}
	entries, err := parseKeychain(ctx, data, unwrap, nil)
	if err != nil {
		return nil, fmt.Errorf("kv: keychain %q: %w", path, err)
	}
	k := &Keychain{entries: entries, unwrap: unwrap, path: path, now: time.Now, fileMod: info.ModTime(), fileSize: info.Size()}
	for _, opt := range opts {
		opt(k)
	}
	k.checkedAt.Store(k.now().UnixNano())
	return k, nil
}

// parseKeychain reads and unwraps the entries, taking from known those the file has unchanged.
func parseKeychain(ctx context.Context, data []byte, unwrap Unwrapper, known []keychainEntry) ([]keychainEntry, error) {
	if len(data) > maxKeyringFile {
		return nil, errors.New("kv: keychain is too large")
	}
	var file []keychainFileEntry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("kv: keychain is not a JSON array of entries: %w", err)
	}
	if len(file) == 0 {
		return nil, errors.New("kv: keychain has no entry")
	}
	entries := make([]keychainEntry, 0, len(file))
	fail := func(err error) ([]keychainEntry, error) {
		for _, e := range entries {
			if !slices.ContainsFunc(known, func(k keychainEntry) bool { return k.id == e.id && k.wrapped == e.wrapped }) {
				clear(e.seal)
				clear(e.name)
			}
		}
		return nil, err
	}
	for _, f := range file {
		match := keychainEntryID.FindStringSubmatch(f.ID)
		if match == nil || len(f.ID) > maxKeyIDLen {
			return fail(fmt.Errorf("kv: keychain entry %q: the ID must end in -v<N> and have at most %d characters", f.ID, maxKeyIDLen))
		}
		version, _ := strconv.Atoi(match[1])
		if f.KEKID == "" || f.ActiveFrom.IsZero() {
			return fail(fmt.Errorf("kv: keychain entry %q: kekId and activeFrom are required", f.ID))
		}
		entry := keychainEntry{id: f.ID, version: version, activeFrom: f.ActiveFrom, wrapped: f.Keys}
		if i := slices.IndexFunc(known, func(k keychainEntry) bool { return k.id == f.ID && k.wrapped == f.Keys }); i >= 0 {
			entry.seal, entry.name = known[i].seal, known[i].name
		} else {
			wrapped, err := base64.StdEncoding.DecodeString(f.Keys)
			if err != nil || len(wrapped) != keychainIVSize+2*keySize+keychainTagSize {
				return fail(fmt.Errorf("kv: keychain entry %q: keys must be the base64 of IV, two wrapped keys and tag", f.ID))
			}
			aad := f.ID
			if f.Emergency {
				aad += "/emergency"
			}
			bounded, cancel := context.WithTimeout(ctx, keychainUnwrapTimeout)
			keys, err := unwrap.Unwrap(bounded, f.KEKID, wrapped[:keychainIVSize], wrapped[keychainIVSize:len(wrapped)-keychainTagSize], wrapped[len(wrapped)-keychainTagSize:], []byte(aad))
			cancel()
			if err != nil {
				return fail(fmt.Errorf("kv: keychain entry %q is not unwrapped: %w", f.ID, err))
			}
			if len(keys) != 2*keySize {
				clear(keys)
				return fail(fmt.Errorf("kv: keychain entry %q: unwrapped %d bytes, want two keys", f.ID, len(keys)))
			}
			entry.seal, entry.name = keys[:keySize:keySize], keys[keySize:]
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b keychainEntry) int { return a.version - b.version })
	for i := 1; i < len(entries); i++ {
		if entries[i].version == entries[i-1].version || entries[i].id == entries[i-1].id {
			return fail(fmt.Errorf("kv: keychain has version %d twice", entries[i].version))
		}
		if !entries[i].activeFrom.After(entries[i-1].activeFrom) {
			return fail(fmt.Errorf("kv: keychain entry %q is active before the version below it", entries[i].id))
		}
	}
	return entries, nil
}

// current is the entry that seals: the highest version whose time has come and that the replicas agree on.
// None is while the time of the first entry has not come.
func (k *Keychain) current() (keychainEntry, bool) {
	now := k.now()
	for _, entry := range slices.Backward(k.entries) {
		if !entry.activeFrom.After(now) && (k.agreed == nil || k.agreed(entry.id)) {
			return entry, true
		}
	}
	return keychainEntry{}, false
}

// Ready returns the IDs of the entries whose time has come by this replica's clock, whatever the others say:
// what it tells them it is ready for.
func (k *Keychain) Ready() []string {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	now := k.now()
	var ids []string
	for _, entry := range k.entries {
		if !entry.activeFrom.After(now) {
			ids = append(ids, entry.id)
		}
	}
	return ids
}

// Current implements [Keys]. Before the first entry is active there is no current key and the ID is empty:
// a keychain that takes over from other keys is rolled out with an entry for later, and until then those
// keys seal.
func (k *Keychain) Current() (string, []byte) {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	entry, _ := k.current()
	return entry.id, slices.Clone(entry.seal)
}

// Lookup implements [Keys].
func (k *Keychain) Lookup(id string) ([]byte, bool) {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, entry := range k.entries {
		if entry.id == id {
			return slices.Clone(entry.seal), true
		}
	}
	return nil, false
}

// NameKeys returns the name keys of all entries, that of the current entry first and then from the newest
// to the oldest: the order in which to look for something that was named under any of them. While no entry
// is active, none comes first. The slices are fresh copies the caller owns and clears.
func (k *Keychain) NameKeys() []NameKey {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	var keys []NameKey
	current, active := k.current()
	if active {
		keys = append(keys, NameKey{ID: current.id, Key: slices.Clone(current.name), Since: current.activeFrom})
	}
	for _, entry := range slices.Backward(k.entries) {
		if entry.id != current.id {
			keys = append(keys, NameKey{ID: entry.id, Key: slices.Clone(entry.name), Since: entry.activeFrom})
		}
	}
	return keys
}

// String names the entries and never a key, so that a keychain in a log line or a %v leaks nothing.
func (k *Keychain) String() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	current, _ := k.current()
	return fmt.Sprintf("kv.Keychain{current: %q, entries: %d}", current.id, len(k.entries))
}

// GoString keeps %#v as silent as %v.
func (k *Keychain) GoString() string { return k.String() }

func (k *Keychain) followFile() {
	if k.path == "" {
		return
	}
	now := k.now().UnixNano()
	checked := k.checkedAt.Load()
	if now-checked < int64(keyringCheckEvery) || !k.checkedAt.CompareAndSwap(checked, now) {
		return
	}
	k.reloadLock.Lock()
	defer k.reloadLock.Unlock()
	if err := k.reload(); err != nil {
		slog.Error("kv: reloading the keychain failed, keeping the keys in force", "path", k.path, "error", err)
	}
}

func (k *Keychain) reload() error {
	info, data, err := readKeyringFile(k.path)
	if err != nil {
		return err
	}
	if info.ModTime().Equal(k.fileMod) && info.Size() == k.fileSize {
		return nil
	}
	k.mu.RLock()
	known := slices.Clone(k.entries)
	k.mu.RUnlock()
	entries, err := parseKeychain(context.Background(), data, k.unwrap, known)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.entries = entries
	k.mu.Unlock()
	for _, old := range known {
		if !slices.ContainsFunc(entries, func(e keychainEntry) bool { return e.id == old.id && e.wrapped == old.wrapped }) {
			clear(old.seal)
			clear(old.name)
		}
	}
	k.fileMod, k.fileSize = info.ModTime(), info.Size()
	current, _ := k.current()
	slog.Info("kv: keychain reloaded", "path", k.path, "current", current.id, "entries", len(entries))
	return nil
}

// LocalKEK is a key-encryption key held in memory, for development and for tests: an [Unwrapper] for
// installations without a key service, and the means to make a keychain entry for them. Whatever key ID an
// entry names, it is this key.
type LocalKEK []byte

func (kek LocalKEK) aead() (cipher.AEAD, error) {
	if len(kek) != keySize {
		return nil, fmt.Errorf("kv: a key-encryption key has %d bytes", keySize)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Unwrap implements [Unwrapper].
func (kek LocalKEK) Unwrap(_ context.Context, _ string, iv, ciphertext, tag, associatedData []byte) ([]byte, error) {
	aead, err := kek.aead()
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() {
		return nil, errors.New("kv: wrong IV size")
	}
	return aead.Open(nil, iv, slices.Concat(ciphertext, tag), associatedData)
}

// NewEntry makes fresh keys and returns them as one keychain entry, wrapped under this key: one element of
// the JSON array a keychain file is.
func (kek LocalKEK) NewEntry(id, kekID string, activeFrom time.Time) ([]byte, error) {
	aead, err := kek.aead()
	if err != nil {
		return nil, err
	}
	if !keychainEntryID.MatchString(id) {
		return nil, fmt.Errorf("kv: keychain entry %q: the ID must end in -v<N>", id)
	}
	material := make([]byte, keychainIVSize+2*keySize)
	defer clear(material)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}
	iv, keys := material[:keychainIVSize], material[keychainIVSize:]
	wrapped := aead.Seal(slices.Clone(iv), iv, keys, []byte(id))
	return json.Marshal(keychainFileEntry{ID: id, KEKID: kekID, ActiveFrom: activeFrom.UTC(), Keys: base64.StdEncoding.EncodeToString(wrapped)})
}
