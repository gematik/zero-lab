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

package zaddy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

const (
	nonceKeySize = 32
	// maxNonceKeyID and maxNonceKeyFile are those of kv's keyring, so that one file serves both.
	maxNonceKeyID   = 64
	maxNonceKeyFile = 64 << 10
	// bareNonceKeyID is the ID of the one key of a file that holds a bare key, as in kv's keyring.
	bareNonceKeyID = "default"
)

// nonceKeys are the keys the DPoP nonces are sealed under, read once from a file in the format of kv's keyring:
// `<id> <base64 of 32 bytes>` per line, the first current, `#` comments and blank lines ignored; or one bare
// key. Caddy provisions the app again on a config reload, which is when a rotated file takes effect.
type nonceKeys struct {
	current string
	keys    map[string][]byte
}

// loadNonceKeys reads the key file at path. Its errors name line numbers, never the content of a line.
func loadNonceKeys(path string) (*nonceKeys, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxNonceKeyFile+1))
	defer clear(data)
	if err != nil {
		return nil, err
	}
	keys, err := parseNonceKeys(data)
	if err != nil {
		return nil, fmt.Errorf("key file %q: %w", path, err)
	}
	return keys, nil
}

func parseNonceKeys(data []byte) (*nonceKeys, error) {
	if len(data) > maxNonceKeyFile {
		return nil, errors.New("key file too large")
	}
	k := &nonceKeys{keys: make(map[string][]byte)}
	fail := func(line int, reason string) (*nonceKeys, error) {
		for _, key := range k.keys {
			clear(key)
		}
		return nil, fmt.Errorf("line %d: %s", line, reason)
	}
	bare := false
	for i, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := bytes.Fields(line)
		var id string
		switch {
		case len(fields) == 1 && !bare && len(k.keys) == 0:
			bare, id = true, bareNonceKeyID
		case len(fields) == 1 || len(fields) == 2 && bare:
			return fail(i+1, "a bare key must be the only key in the file")
		case len(fields) == 2:
			id = string(fields[0])
			if !validNonceKeyID(id) {
				return fail(i+1, fmt.Sprintf("a key ID is 1 to %d letters, digits, '.', '_' or '-'", maxNonceKeyID))
			}
			if _, dup := k.keys[id]; dup {
				return fail(i+1, "duplicate key ID")
			}
		default:
			return fail(i+1, "expected `<id> <base64 of 32 bytes>`")
		}
		encoded := fields[len(fields)-1]
		key := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
		n, err := base64.StdEncoding.Strict().Decode(key, encoded)
		if err != nil || n != nonceKeySize || len(encoded) != base64.StdEncoding.EncodedLen(nonceKeySize) {
			clear(key)
			return fail(i+1, "a key is the standard base64 of 32 bytes")
		}
		k.keys[id] = key[:nonceKeySize]
		if k.current == "" {
			k.current = id
		}
	}
	if len(k.keys) == 0 {
		return nil, errors.New("no keys")
	}
	return k, nil
}

func validNonceKeyID(id string) bool {
	if len(id) == 0 || len(id) > maxNonceKeyID {
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

// Current implements nonce.Keys.
func (k *nonceKeys) Current() (string, []byte) {
	return k.current, slices.Clone(k.keys[k.current])
}

// Lookup implements nonce.Keys.
func (k *nonceKeys) Lookup(id string) ([]byte, bool) {
	key, ok := k.keys[id]
	if !ok {
		return nil, false
	}
	return slices.Clone(key), true
}
