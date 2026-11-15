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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

// kvSessions implements proxy.SessionStore over a kv.Store: the record under "pep:session:<id>" plus a
// "pep:state:<hash of the state>" index holding the id, written in one SetMany.
type kvSessions struct {
	store kv.Store
}

var _ proxy.SessionStore = kvSessions{}

func newKVSessions(store kv.Store) kvSessions { return kvSessions{store: store} }

func sessionKey(id string) string { return "pep:session:" + id }

// stateKey keeps the login state, a secret, out of the key, which a sealed store leaves in clear (server rule 10).
func stateKey(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "pep:state:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// reportIntegrity logs a record that does not open at error level, since it can mean tampering with the store
// (server rule 14). The proxy treats the session as absent, so the user just logs in again.
func reportIntegrity(record string, err error) error {
	if errors.Is(err, kv.ErrIntegrity) {
		slog.Error("kv record failed its integrity check, treating it as absent", "record", record, "error", err)
	}
	return err
}

// Save implements proxy.SessionStore.
func (k kvSessions) Save(ctx context.Context, s *proxy.Session, ttl time.Duration) error {
	record, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	idValue, err := json.Marshal(s.ID)
	if err != nil {
		return err
	}
	entries := []kv.Entry{{Key: sessionKey(s.ID), Value: record, TTL: ttl}}
	if s.State != "" {
		entries = append(entries, kv.Entry{Key: stateKey(s.State), Value: idValue, TTL: proxy.LoginStateTTL})
	}
	return k.store.SetMany(ctx, entries...)
}

// Load implements proxy.SessionStore.
func (k kvSessions) Load(ctx context.Context, id string) (*proxy.Session, error) {
	data, found, err := k.store.Get(ctx, sessionKey(id))
	if err != nil {
		return nil, reportIntegrity("session", err)
	}
	if !found {
		return nil, proxy.ErrSessionNotFound
	}
	return decodeSession(data)
}

// decodeSession reads a session record. Only zero-pep-proxy writes it, so a member it does not name is refused with
// the rest of what server rule 28 refuses; a replica older than the record's writer treats the session as absent.
func decodeSession(data []byte) (*proxy.Session, error) {
	var s proxy.Session
	if err := json.Unmarshal(data, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &s, nil
}

// SessionID implements proxy.SessionStore.
func (k kvSessions) SessionID(ctx context.Context, state string) (string, error) {
	data, found, err := k.store.Get(ctx, stateKey(state))
	if err != nil {
		return "", reportIntegrity("login state", err)
	}
	if !found {
		return "", proxy.ErrSessionNotFound
	}
	var id string
	if err := json.Unmarshal(data, &id); err != nil {
		return "", err
	}
	return id, nil
}

// Delete implements proxy.SessionStore.
func (k kvSessions) Delete(ctx context.Context, id string) error {
	return k.store.Delete(ctx, sessionKey(id))
}

// DeleteState implements proxy.SessionStore.
func (k kvSessions) DeleteState(ctx context.Context, state string) error {
	return k.store.Delete(ctx, stateKey(state))
}
