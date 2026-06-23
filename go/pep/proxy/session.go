package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/segmentio/ksuid"
)

const defaultSessionTTL = time.Hour

// Session is the server-side login session. The browser only ever holds an opaque, HttpOnly cookie with
// the ID; tokens and identity stay here (the BCP token-mediating property). IDPIss records which provider
// the login is/was driven against so the callback can resolve the same client.
type Session struct {
	ID                   string         `json:"id"`
	IDPIss               string         `json:"idp_iss,omitempty"`
	State                string         `json:"state"`
	Nonce                string         `json:"nonce"`
	CodeVerifier         string         `json:"code_verifier"`
	CodeChallengeMethod  string         `json:"code_challenge_method"`
	AccessToken          string         `json:"access_token,omitempty"`
	RefreshToken         string         `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt time.Time      `json:"access_token_expires_at,omitempty"`
	Identity             map[string]any `json:"identity,omitempty"`
	ReturnTo             string         `json:"return_to,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
}

// Authenticated reports whether the login completed (identity captured).
func (s *Session) Authenticated() bool { return len(s.Identity) > 0 }

// sessionStore persists sessions in a kv.Store: the record under "pep:session:<id>" plus a
// "pep:state:<state>" index → id. Each save refreshes the TTL (sliding expiry); the record + index are
// written in one atomic SetMany so a state lookup never resolves a half-written record.
type sessionStore struct {
	store kv.Store
	ttl   time.Duration
}

func newSessionStore(store kv.Store, ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &sessionStore{store: store, ttl: ttl}
}

func sessionKey(id string) string  { return "pep:session:" + id }
func stateKey(state string) string { return "pep:state:" + state }

func (m *sessionStore) create() *Session {
	return &Session{ID: ksuid.New().String(), CreatedAt: time.Now()}
}

func (m *sessionStore) save(s *Session) error {
	record, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	idValue, err := json.Marshal(s.ID)
	if err != nil {
		return err
	}
	entries := []kv.Entry{{Key: sessionKey(s.ID), Value: record, TTL: m.ttl}}
	if s.State != "" {
		entries = append(entries, kv.Entry{Key: stateKey(s.State), Value: idValue, TTL: m.ttl})
	}
	return m.store.SetMany(context.Background(), entries...)
}

func (m *sessionStore) byID(id string) (*Session, error) {
	data, found, err := m.store.Get(context.Background(), sessionKey(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("session %q not found", id)
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &s, nil
}

func (m *sessionStore) byState(state string) (*Session, error) {
	idData, found, err := m.store.Get(context.Background(), stateKey(state))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("session for state %q not found", state)
	}
	var id string
	if err := json.Unmarshal(idData, &id); err != nil {
		return nil, err
	}
	return m.byID(id)
}

func (m *sessionStore) deleteByID(id string) error {
	s, err := m.byID(id)
	if err != nil {
		return err
	}
	ctx := context.Background()
	_ = m.store.Delete(ctx, sessionKey(id))
	if s.State != "" {
		_ = m.store.Delete(ctx, stateKey(s.State))
	}
	return nil
}
