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
	"slices"
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

// The names of the keys an entry of a [Keychain] can hold.
const (
	// KeychainSeal is the key that seals, which every entry has.
	KeychainSeal = "seal"
	// KeychainName is the key for names, which an entry has when the names are to change.
	KeychainName = "name"
)

// Unwrapper is the key service that holds the key-encryption keys of a [Keychain]: an HSM, a KMS, or for
// development a key in a file ([LocalKEK]). The key-encryption key never leaves it; what it hands out is the
// key material of one entry.
type Unwrapper interface {
	// Unwrap decrypts what was encrypted under the key kekID with AES-256-GCM, and fails if the associated
	// data is not the one it was encrypted with. The plaintext is the caller's, to clear.
	Unwrap(ctx context.Context, kekID string, iv, ciphertext, tag, associatedData []byte) ([]byte, error)
}

// NameKey is a key of a keychain for deriving names: pseudonyms of what must not stand in a database key in
// the clear.
type NameKey struct {
	// ID is the ID of the entry that brought the key.
	ID  string
	Key []byte
	// Since is from when that entry is in force by its own word.
	Since time.Time
}

// KeychainEntry is what a keychain file says of one entry, without its keys.
type KeychainEntry struct {
	ID         string
	Version    int
	ActiveFrom time.Time
	KEKID      string
	// Keys names the keys the entry holds, sorted.
	Keys []string
}

// Keychain is the keys of a service that seals what it stores, in one file: entries of rising version, each
// holding named keys that are wrapped together under a key-encryption key an [Unwrapper] holds (envelope
// encryption, server rule 19). No key stands in the file in the clear, so it may lie where the data does;
// the key-encryption key must not.
//
//	{
//	  "purpose": "<what the keys are for>",
//	  "entries": [
//	    {"id": "v2", "version": 2, "activeFrom": "<RFC 3339>", "kekId": "…",
//	     "keys": ["name", "seal"], "wrapped": "<base64 of IV, ciphertext, tag>"}
//	  ],
//	  "revoked": ["v1"]
//	}
//
// What is wrapped is a JSON object of the named keys, 32 bytes each in base64. Everything else an entry
// says, and the purpose of the file, is the associated data of the wrapping: nobody who cannot wrap can put
// an entry to another use, give it another time, or move it to another file.
//
// Every entry has the key [KeychainSeal]. The newest entry whose time has come seals; every entry opens.
// An entry has the key [KeychainName] only when the names are to change, which costs a service far more
// than a new key for sealing: the name key in force is that of the newest entry at or below the sealing one
// that has one.
//
// Changing the keys (server rule 22): add an entry with the next version and a time by which every replica
// has the file; take along what has to outlive the entry of before; then drop that entry. revoked names
// entries that were dropped although something they sealed is still there, which a consumer that watches
// over that otherwise refuses ([WithKeychainCheck]). A keychain from [LoadKeychain] follows its file, so
// nothing needs a restart.
type Keychain struct {
	mu      sync.RWMutex
	entries []keychainEntry // by version, rising
	revoked []string

	purpose    string
	unwrap     Unwrapper
	agreed     func(id string) bool
	check      func(entries []KeychainEntry, revoked []string) error
	path       string
	now        func() time.Time
	checkedAt  atomic.Int64
	fileMod    time.Time
	fileSize   int64
	reloadLock sync.Mutex
}

type keychainEntry struct {
	KeychainEntry
	wrapped    string
	seal, name []byte
}

func (e keychainEntry) clear() {
	clear(e.seal)
	clear(e.name)
}

// keychainFile is the file.
type keychainFile struct {
	Purpose string              `json:"purpose"`
	Entries []keychainFileEntry `json:"entries"`
	Revoked []string            `json:"revoked,omitempty"`
}

type keychainFileEntry struct {
	ID         string    `json:"id"`
	Version    int       `json:"version"`
	ActiveFrom time.Time `json:"activeFrom"`
	KEKID      string    `json:"kekId"`
	Keys       []string  `json:"keys"`
	Wrapped    string    `json:"wrapped"`
}

// associatedData is what the wrapping of an entry is bound to: all the file says of it, and the purpose.
func (e keychainFileEntry) associatedData(purpose string) []byte {
	bound, _ := json.Marshal(struct {
		Purpose    string   `json:"purpose"`
		ID         string   `json:"id"`
		Version    int      `json:"version"`
		ActiveFrom string   `json:"activeFrom"`
		KEKID      string   `json:"kekId"`
		Keys       []string `json:"keys"`
	}{purpose, e.ID, e.Version, e.ActiveFrom.UTC().Format(time.RFC3339Nano), e.KEKID, e.Keys})
	return bound
}

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

// WithKeychainCheck has check look at a changed file before its keys take the place of those in force: an
// error keeps the keys in force, as a file that cannot be read does. A consumer refuses with it a file that
// lacks an entry something is still sealed under. The file a keychain is first made from is not checked;
// [Keychain.Entries] and [Keychain.Revoked] say what it holds.
func WithKeychainCheck(check func(entries []KeychainEntry, revoked []string) error) KeychainOption {
	return func(k *Keychain) { k.check = check }
}

// ParseKeychain unwraps the entries of a keychain file for the given purpose. The keychain does not follow
// a file.
func ParseKeychain(ctx context.Context, data []byte, purpose string, unwrap Unwrapper, opts ...KeychainOption) (*Keychain, error) {
	entries, revoked, err := parseKeychain(ctx, data, purpose, unwrap, nil)
	if err != nil {
		return nil, err
	}
	k := &Keychain{entries: entries, revoked: revoked, purpose: purpose, unwrap: unwrap, now: time.Now}
	for _, opt := range opts {
		opt(k)
	}
	return k, nil
}

// LoadKeychain reads a keychain for the given purpose from the file at path, unwraps its entries, and keeps
// following the file as [LoadKeyring] does: a changed file is read again within 30 s, only its new entries
// are unwrapped, and a reload that fails keeps the keys in force and logs at error level until it succeeds.
func LoadKeychain(ctx context.Context, path, purpose string, unwrap Unwrapper, opts ...KeychainOption) (*Keychain, error) {
	info, data, err := readKeyringFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ParseKeychain(ctx, data, purpose, unwrap, opts...)
	if err != nil {
		return nil, fmt.Errorf("kv: keychain %q: %w", path, err)
	}
	k.path, k.fileMod, k.fileSize = path, info.ModTime(), info.Size()
	k.checkedAt.Store(k.now().UnixNano())
	return k, nil
}

// parseKeychain reads and unwraps the entries, taking from known those the file has unchanged.
func parseKeychain(ctx context.Context, data []byte, purpose string, unwrap Unwrapper, known []keychainEntry) ([]keychainEntry, []string, error) {
	if len(data) > maxKeyringFile {
		return nil, nil, errors.New("kv: keychain is too large")
	}
	var file keychainFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, nil, fmt.Errorf("kv: keychain is not read: %w", err)
	}
	if file.Purpose != purpose || purpose == "" {
		return nil, nil, fmt.Errorf("kv: keychain is for %q, not for %q", file.Purpose, purpose)
	}
	if len(file.Entries) == 0 {
		return nil, nil, errors.New("kv: keychain has no entry")
	}
	entries := make([]keychainEntry, 0, len(file.Entries))
	isKnown := func(e keychainEntry) bool {
		return slices.ContainsFunc(known, func(k keychainEntry) bool { return k.ID == e.ID && k.wrapped == e.wrapped })
	}
	fail := func(err error) ([]keychainEntry, []string, error) {
		for _, e := range entries {
			if !isKnown(e) {
				e.clear()
			}
		}
		return nil, nil, err
	}
	for _, f := range file.Entries {
		if !validKeyID(f.ID) || f.Version < 1 || f.KEKID == "" || f.ActiveFrom.IsZero() {
			return fail(fmt.Errorf("kv: keychain entry %q needs an id, a version from 1, kekId and activeFrom", f.ID))
		}
		if !slices.IsSorted(f.Keys) || len(slices.Compact(slices.Clone(f.Keys))) != len(f.Keys) || !slices.Contains(f.Keys, KeychainSeal) {
			return fail(fmt.Errorf("kv: keychain entry %q: keys must be sorted, each once, and have %q", f.ID, KeychainSeal))
		}
		entry := keychainEntry{ID: f.ID, Version: f.Version, ActiveFrom: f.ActiveFrom, KEKID: f.KEKID, Keys: f.Keys, wrapped: f.Wrapped}
		if i := slices.IndexFunc(known, func(k keychainEntry) bool { return k.ID == f.ID && k.wrapped == f.Wrapped }); i >= 0 &&
			slices.Equal(known[i].Keys, f.Keys) && known[i].Version == f.Version && known[i].ActiveFrom.Equal(f.ActiveFrom) && known[i].KEKID == f.KEKID {
			entry.seal, entry.name = known[i].seal, known[i].name
		} else {
			wrapped, err := base64.StdEncoding.DecodeString(f.Wrapped)
			if err != nil || len(wrapped) <= keychainIVSize+keychainTagSize {
				return fail(fmt.Errorf("kv: keychain entry %q: wrapped must be the base64 of IV, wrapped keys and tag", f.ID))
			}
			bounded, cancel := context.WithTimeout(ctx, keychainUnwrapTimeout)
			plain, err := unwrap.Unwrap(bounded, f.KEKID, wrapped[:keychainIVSize], wrapped[keychainIVSize:len(wrapped)-keychainTagSize], wrapped[len(wrapped)-keychainTagSize:], f.associatedData(purpose))
			cancel()
			if err != nil {
				return fail(fmt.Errorf("kv: keychain entry %q is not unwrapped: %w", f.ID, err))
			}
			var keys map[string][]byte
			err = json.Unmarshal(plain, &keys)
			clear(plain)
			if err != nil || len(keys) != len(f.Keys) {
				return fail(fmt.Errorf("kv: keychain entry %q does not hold the keys it names", f.ID))
			}
			for _, name := range f.Keys {
				if len(keys[name]) != keySize {
					return fail(fmt.Errorf("kv: keychain entry %q: the key %q is not one of %d bytes", f.ID, name, keySize))
				}
			}
			entry.seal, entry.name = keys[KeychainSeal], keys[KeychainName]
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b keychainEntry) int { return a.Version - b.Version })
	for i := 1; i < len(entries); i++ {
		if entries[i].Version == entries[i-1].Version || slices.ContainsFunc(entries[:i], func(e keychainEntry) bool { return e.ID == entries[i].ID }) {
			return fail(fmt.Errorf("kv: keychain has version %d or the id %q twice", entries[i].Version, entries[i].ID))
		}
		if !entries[i].ActiveFrom.After(entries[i-1].ActiveFrom) {
			return fail(fmt.Errorf("kv: keychain entry %q is active before the version below it", entries[i].ID))
		}
	}
	if !slices.ContainsFunc(entries, func(e keychainEntry) bool { return e.name != nil }) {
		return fail(fmt.Errorf("kv: no entry of the keychain has the key %q", KeychainName))
	}
	for _, id := range file.Revoked {
		if slices.ContainsFunc(entries, func(e keychainEntry) bool { return e.ID == id }) {
			return fail(fmt.Errorf("kv: keychain entry %q is there and revoked", id))
		}
	}
	return entries, file.Revoked, nil
}

// current is the entry that seals: the highest version whose time has come and that the replicas agree on.
// None is while the time of the first entry has not come.
func (k *Keychain) current() (keychainEntry, bool) {
	now := k.now()
	for _, entry := range slices.Backward(k.entries) {
		if !entry.ActiveFrom.After(now) && (k.agreed == nil || k.agreed(entry.ID)) {
			return entry, true
		}
	}
	return keychainEntry{}, false
}

// Entries returns what the file says of each entry, by rising version.
func (k *Keychain) Entries() []KeychainEntry {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	entries := make([]KeychainEntry, len(k.entries))
	for i, entry := range k.entries {
		entries[i] = entry.KeychainEntry
	}
	return entries
}

// Revoked returns the IDs of the entries the file says were dropped with what they sealed.
func (k *Keychain) Revoked() []string {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.Clone(k.revoked)
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
		if !entry.ActiveFrom.After(now) {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}

// Current implements [Keys]. Before the first entry is in force there is no current key and the ID is empty.
func (k *Keychain) Current() (string, []byte) {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	entry, _ := k.current()
	return entry.ID, slices.Clone(entry.seal)
}

// Lookup implements [Keys].
func (k *Keychain) Lookup(id string) ([]byte, bool) {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, entry := range k.entries {
		if entry.ID == id {
			return slices.Clone(entry.seal), true
		}
	}
	return nil, false
}

// NameKeys returns the name keys of the entries that have one. The key in force comes first: that of the
// newest entry at or below the one that seals. The others follow from the newest to the oldest, the order
// in which to look for something that was named under any of them. While no entry is in force, none comes
// first. The slices are fresh copies the caller owns and clears.
func (k *Keychain) NameKeys() []NameKey {
	k.followFile()
	k.mu.RLock()
	defer k.mu.RUnlock()
	var keys []NameKey
	first := ""
	if current, active := k.current(); active {
		for _, entry := range slices.Backward(k.entries) {
			if entry.name != nil && entry.Version <= current.Version {
				first = entry.ID
				keys = append(keys, NameKey{ID: entry.ID, Key: slices.Clone(entry.name), Since: entry.ActiveFrom})
				break
			}
		}
	}
	for _, entry := range slices.Backward(k.entries) {
		if entry.name != nil && entry.ID != first {
			keys = append(keys, NameKey{ID: entry.ID, Key: slices.Clone(entry.name), Since: entry.ActiveFrom})
		}
	}
	return keys
}

// String names the entries and never a key, so that a keychain in a log line or a %v leaks nothing.
func (k *Keychain) String() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	current, _ := k.current()
	return fmt.Sprintf("kv.Keychain{purpose: %q, current: %q, entries: %d}", k.purpose, current.ID, len(k.entries))
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
		slog.Error("kv: the changed keychain is not taken, the keys in force stay", "path", k.path, "error", err)
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
	entries, revoked, err := parseKeychain(context.Background(), data, k.purpose, k.unwrap, known)
	if err != nil {
		return err
	}
	isIn := func(in []keychainEntry, e keychainEntry) bool {
		return slices.ContainsFunc(in, func(o keychainEntry) bool { return o.ID == e.ID && o.wrapped == e.wrapped })
	}
	if k.check != nil {
		said := make([]KeychainEntry, len(entries))
		for i, entry := range entries {
			said[i] = entry.KeychainEntry
		}
		if err := k.check(said, revoked); err != nil {
			for _, entry := range entries {
				if !isIn(known, entry) {
					entry.clear()
				}
			}
			return err
		}
	}
	k.mu.Lock()
	k.entries, k.revoked = entries, revoked
	k.mu.Unlock()
	for _, old := range known {
		if !isIn(entries, old) {
			old.clear()
		}
	}
	k.fileMod, k.fileSize = info.ModTime(), info.Size()
	current, _ := k.current()
	slog.Info("kv: keychain reloaded", "path", k.path, "current", current.ID, "entries", len(entries))
	return nil
}

// LocalKEK is a key-encryption key held in memory, for development and for tests: an [Unwrapper] for
// installations without a key service, and the means to make a keychain for them. Whatever key ID an
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

// Extend returns the keychain file with one entry more, of fresh keys wrapped under this key: the first
// entry of a new file for the purpose when file is empty, else the next version of the file given. The
// entry has the ID "v" and its version, is in force from activeFrom, and holds a key for sealing and, if
// names is set or the entry is the first, one for names.
func (kek LocalKEK) Extend(file []byte, purpose, kekID string, activeFrom time.Time, names bool) ([]byte, error) {
	aead, err := kek.aead()
	if err != nil {
		return nil, err
	}
	chain := keychainFile{Purpose: purpose}
	if len(bytes.TrimSpace(file)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(file))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&chain); err != nil {
			return nil, fmt.Errorf("kv: keychain is not read: %w", err)
		}
		if chain.Purpose != purpose {
			return nil, fmt.Errorf("kv: keychain is for %q, not for %q", chain.Purpose, purpose)
		}
	}
	entry := keychainFileEntry{Version: 1, ActiveFrom: activeFrom.UTC(), KEKID: kekID, Keys: []string{KeychainSeal}}
	for _, e := range chain.Entries {
		entry.Version = max(entry.Version, e.Version+1)
	}
	entry.ID = fmt.Sprintf("v%d", entry.Version)
	if names || len(chain.Entries) == 0 {
		entry.Keys = []string{KeychainName, KeychainSeal}
	}
	keys := make(map[string][]byte, len(entry.Keys))
	for _, name := range entry.Keys {
		keys[name] = make([]byte, keySize)
		if _, err := rand.Read(keys[name]); err != nil {
			return nil, err
		}
	}
	plain, err := json.Marshal(keys)
	for _, key := range keys {
		clear(key)
	}
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	iv := make([]byte, keychainIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	entry.Wrapped = base64.StdEncoding.EncodeToString(aead.Seal(slices.Clone(iv), iv, plain, entry.associatedData(purpose)))
	chain.Entries = append(chain.Entries, entry)
	return json.MarshalIndent(chain, "", "  ")
}
