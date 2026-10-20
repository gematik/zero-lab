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

package bff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/gematik/zero-lab/go/kv"
)

const defaultBffSessionTTL = time.Hour

// kvSessionManager implements SessionManager over a kv.Store: the session record lives under
// "bff:session:<id>" and "bff:state:<state>" indexes the id. Each write refreshes the TTL (sliding
// expiry), so an active session stays alive while idle ones are reaped.
type kvSessionManager struct {
	store kv.Store
	ttl   time.Duration
}

// NewSessionManager returns a SessionManager backed by store. ttl <= 0 uses the default.
func NewSessionManager(store kv.Store, ttl time.Duration) SessionManager {
	if ttl <= 0 {
		ttl = defaultBffSessionTTL
	}
	return &kvSessionManager{store: store, ttl: ttl}
}

// logRef names a session ID or state in logs without revealing it: the session ID is the
// cookie's value and the state guards the login, so logs carry only the first 8 bytes of
// their SHA-256, enough to correlate entries (servers rule 5).
func logRef(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

func bffSessionKey(id string) string  { return "bff:session:" + id }
func bffStateKey(state string) string { return "bff:state:" + state }

func (m *kvSessionManager) save(session *Session) error {
	record, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	idValue, err := json.Marshal(session.ID)
	if err != nil {
		return err
	}
	return m.store.SetMany(context.Background(),
		kv.Entry{Key: bffSessionKey(session.ID), Value: record, TTL: m.ttl},
		kv.Entry{Key: bffStateKey(session.State), Value: idValue, TTL: m.ttl},
	)
}

func (m *kvSessionManager) CreateSession(state, codeVerifier, codeChallengeMethod string) (*Session, error) {
	session := &Session{
		ID:                  uuid.NewV4().String(),
		State:               state,
		CreatedAt:           time.Now(),
		CodeVerifier:        codeVerifier,
		CodeChallengeMethod: codeChallengeMethod,
	}
	if err := m.save(session); err != nil {
		return nil, err
	}
	slog.Info("session created", "session", logRef(session.ID), "state", logRef(session.State))
	return session, nil
}

func (m *kvSessionManager) UpdateSession(session *Session) error {
	if err := m.save(session); err != nil {
		return err
	}
	slog.Info("session updated", "session", logRef(session.ID), "state", logRef(session.State))
	return nil
}

func (m *kvSessionManager) GetSessionByID(id string) (*Session, error) {
	data, found, err := m.store.Get(context.Background(), bffSessionKey(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("session %s not found", logRef(id))
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &s, nil
}

func (m *kvSessionManager) GetSessionByState(state string) (*Session, error) {
	idData, found, err := m.store.Get(context.Background(), bffStateKey(state))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("session for state %s not found", logRef(state))
	}
	var id string
	if err := json.Unmarshal(idData, &id); err != nil {
		return nil, err
	}
	return m.GetSessionByID(id)
}

func (m *kvSessionManager) DeleteSessionByID(id string) error {
	session, err := m.GetSessionByID(id)
	if err != nil {
		return err
	}
	ctx := context.Background()
	_ = m.store.Delete(ctx, bffSessionKey(id))
	if session.State != "" {
		_ = m.store.Delete(ctx, bffStateKey(session.State))
	}
	slog.Info("session deleted", "session", logRef(session.ID), "state", logRef(session.State))
	return nil
}
