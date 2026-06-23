package bff

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/segmentio/ksuid"
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
		ID:                  ksuid.New().String(),
		State:               state,
		CreatedAt:           time.Now(),
		CodeVerifier:        codeVerifier,
		CodeChallengeMethod: codeChallengeMethod,
	}
	if err := m.save(session); err != nil {
		return nil, err
	}
	slog.Info("session created", "id", session.ID, "state", session.State)
	return session, nil
}

func (m *kvSessionManager) UpdateSession(session *Session) error {
	if err := m.save(session); err != nil {
		return err
	}
	slog.Info("session updated", "id", session.ID, "state", session.State)
	return nil
}

func (m *kvSessionManager) GetSessionByID(id string) (*Session, error) {
	data, found, err := m.store.Get(context.Background(), bffSessionKey(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("session with id '%s' not found", id)
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
		return nil, fmt.Errorf("session with state '%s' not found", state)
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
	slog.Info("session deleted", "id", session.ID, "state", session.State)
	return nil
}
