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

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"

	"github.com/gematik/zero-lab/go/pep"
)

// snapshotClaims is the encrypted session-snapshot payload: enough for /oauth2/auth to emit the identity
// headers locally, the session id (for the revoked-set check), and an absolute expiry. It carries the full
// identity map so the fast path reproduces every header the kv path emits.
type snapshotClaims struct {
	SID      string         `json:"sid"`
	Identity map[string]any `json:"id"`
	IssuedAt int64          `json:"iat"`
	Expiry   int64          `json:"exp"`
}

// snapshotter mints and opens session snapshots as a JWE (dir + A256GCM) — an opaque, authenticated-encrypted
// cookie. It is nil when no key file is configured, which disables the fast path. The key is read from a file
// (never an env value, never kv); see docs/stateless-session-validation.md §2.
type snapshotter struct {
	encKey  []byte   // primary key — encrypt + decrypt
	decKeys [][]byte // primary first, optional previous (decrypt only, for rotation overlap)
	ttl     time.Duration
}

func newSnapshotter(keyPath, prevKeyPath string, ttl time.Duration) (*snapshotter, error) {
	if keyPath == "" {
		return nil, nil
	}
	key, err := loadBase64Key(keyPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot key: %w", err)
	}
	s := &snapshotter{encKey: key, decKeys: [][]byte{key}, ttl: ttl}
	if prevKeyPath != "" {
		prev, err := loadBase64Key(prevKeyPath)
		if err != nil {
			return nil, fmt.Errorf("snapshot previous key: %w", err)
		}
		s.decKeys = append(s.decKeys, prev)
	}
	return s, nil
}

// loadBase64Key reads a base64-encoded 256-bit key from a file (the snapshot key and the session-store
// at-rest key share this format).
func loadBase64Key(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("base64-decode key in %q: %w", path, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key in %q must be 32 bytes (256-bit), got %d", path, len(key))
	}
	return key, nil
}

func (s *snapshotter) mint(sid string, identity map[string]any) (string, error) {
	now := time.Now()
	payload, err := json.Marshal(snapshotClaims{
		SID: sid, Identity: identity, IssuedAt: now.Unix(), Expiry: now.Add(s.ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	enc, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), s.encKey), jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		return "", fmt.Errorf("encrypt snapshot: %w", err)
	}
	return string(enc), nil
}

// open decrypts and validates a snapshot via the shared pep validation (so the verifier and zaddy use the
// same code). It returns (claims, true) only when the token decrypts and is unexpired.
func (s *snapshotter) open(token string) (*snapshotClaims, bool) {
	identity, sid, ok := pep.OpenSessionCookie(token, s.decKeys)
	if !ok {
		return nil, false
	}
	return &snapshotClaims{SID: sid, Identity: identity}, true
}
