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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
)

const (
	keySize = 32
	// maxKeyIDLen keeps key IDs short: each one is carried in every sealed record.
	maxKeyIDLen = 64
	// maxKeyringFile is far beyond any real ring and bounds the work of a parse.
	maxKeyringFile = 64 << 10

	// BareKeyID is the ID of the key in a file holding one bare base64 key. A rotation away from such a file
	// names it: `k2 <new key>` above `default <the old key>`.
	BareKeyID = "default"
)

// Keys is where a sealed store gets its key material. It is small so that a ring backed by a KMS can replace
// [Keyring] behind it; go/nonce declares the same shape, so one ring serves both.
type Keys interface {
	// Current returns the key that seals new records. The slice is a fresh copy the caller owns and clears.
	Current() (id string, key []byte)
	// Lookup returns the key with the given ID, for opening. The slice is a fresh copy the caller owns and
	// clears.
	Lookup(id string) (key []byte, ok bool)
}

// Keyring holds several 32-byte keys with IDs: the first one is current and seals, all of them open.
//
// The text format is one key per line, `<id> <base64 of 32 bytes>`, with `#` comments and blank lines ignored.
// A file holding one bare base64 key is a ring of the single key [BareKeyID].
//
// Rotating, so that no replica meets a record it cannot open (server rule 22): add the new key second on all
// pods; once all of them hold it, make it first; drop the old key after the longest TTL of a record it sealed.
// Each step is a rollout (server rule 8): a ring is read once, and a changed file takes effect in the
// processes that start with it.
type Keyring struct {
	mu   sync.RWMutex
	ring keyringData
}

type keyringData struct {
	current string
	keys    map[string][]byte
}

func (d keyringData) clear() {
	for _, key := range d.keys {
		clear(key)
	}
}

// ParseKeyring reads a ring in the text format of [Keyring]. It refuses wrong key lengths, duplicate IDs and
// an empty ring. Its errors name line numbers, never the content of a line.
func ParseKeyring(data []byte) (*Keyring, error) {
	ring, err := parseKeyring(data)
	if err != nil {
		return nil, err
	}
	return &Keyring{ring: ring}, nil
}

// LoadKeyring reads a ring from the file at path, once. The file is not looked at again: a changed file takes
// effect with a new process, a rollout (server rule 8).
func LoadKeyring(path string) (*Keyring, error) {
	data, err := readKeyringFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	ring, err := parseKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("kv: key file %q: %w", path, err)
	}
	return &Keyring{ring: ring}, nil
}

// Current implements [Keys].
func (k *Keyring) Current() (string, []byte) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.ring.current, slices.Clone(k.ring.keys[k.ring.current])
}

// Lookup implements [Keys].
func (k *Keyring) Lookup(id string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.ring.keys[id]
	if !ok {
		return nil, false
	}
	return slices.Clone(key), true
}

// String names the ring without its keys, so that formatting one cannot leak them.
func (k *Keyring) String() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return fmt.Sprintf("kv.Keyring{current: %q, keys: %d}", k.ring.current, len(k.ring.keys))
}

// GoString is String for %#v.
func (k *Keyring) GoString() string { return k.String() }

func readKeyringFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyringFile+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

func parseKeyring(data []byte) (keyringData, error) {
	ring := keyringData{keys: make(map[string][]byte)}
	fail := func(line int, reason string) (keyringData, error) {
		ring.clear()
		return keyringData{}, fmt.Errorf("line %d: %s", line, reason)
	}
	if len(data) > maxKeyringFile {
		return keyringData{}, errors.New("key file too large")
	}
	bare := false
	for i, line := range bytes.Split(data, []byte("\n")) {
		number := i + 1
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := bytes.Fields(line)
		var id string
		switch len(fields) {
		case 1:
			if bare || len(ring.keys) > 0 {
				return fail(number, "a bare key must be the only key in the file")
			}
			bare = true
			id = BareKeyID
		case 2:
			if bare {
				return fail(number, "a bare key must be the only key in the file")
			}
			id = string(fields[0])
			if !validKeyID(id) {
				return fail(number, fmt.Sprintf("a key ID is 1 to %d letters, digits, '.', '_' or '-'", maxKeyIDLen))
			}
			if _, dup := ring.keys[id]; dup {
				return fail(number, "duplicate key ID")
			}
		default:
			return fail(number, "expected `<id> <base64 of 32 bytes>`")
		}
		key, err := decodeKey(fields[len(fields)-1])
		if err != nil {
			return fail(number, err.Error())
		}
		ring.keys[id] = key
		if ring.current == "" {
			ring.current = id
		}
	}
	if len(ring.keys) == 0 {
		return keyringData{}, errors.New("no keys")
	}
	return ring, nil
}

func decodeKey(encoded []byte) ([]byte, error) {
	errLength := errors.New("a key is the standard base64 of 32 bytes")
	if len(encoded) != base64.StdEncoding.EncodedLen(keySize) {
		return nil, errLength
	}
	key := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(key, encoded)
	if err != nil || n != keySize {
		clear(key)
		return nil, errLength
	}
	return key[:n], nil
}

func validKeyID(id string) bool {
	if len(id) == 0 || len(id) > maxKeyIDLen {
		return false
	}
	for _, c := range []byte(id) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
