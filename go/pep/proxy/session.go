package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/segmentio/ksuid"
)

const (
	// defaultSessionTTL is the idle timeout: each save refreshes it (sliding expiry).
	defaultSessionTTL = time.Hour
	// defaultSessionMaxLifetime is the absolute cap from creation, enforced regardless of activity, so an
	// actively-used session cannot live forever (OWASP: both idle and absolute timeouts).
	defaultSessionMaxLifetime = 12 * time.Hour
	// defaultStateTTL bounds the pep:state index to the login window, so an abandoned login's state mapping
	// expires quickly instead of lingering for the whole session TTL.
	defaultStateTTL = 15 * time.Minute
)

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

	// PDP backend: tokens keyed by AS issuer (one entry in S4) and the per-session DPoP private key (JWK
	// JSON). The provider backend leaves both zero. DPoPKeyJWK holds the private key in S4; the T3 stage
	// (see docs/pdp-backend.md §10) moves it to the browser, leaving only the public half here.
	Tokens     map[string]*TokenEntry `json:"tokens,omitempty"`
	DPoPKeyJWK []byte                 `json:"dpop_key_jwk,omitempty"`
}

// TokenEntry is the PDP-issued token set for one authorization server.
type TokenEntry struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// SetTokens stores the token set for an authorization server on the session.
func (s *Session) SetTokens(asIssuer string, e *TokenEntry) {
	if s.Tokens == nil {
		s.Tokens = map[string]*TokenEntry{}
	}
	s.Tokens[asIssuer] = e
}

// GetTokens returns the token set for an authorization server, if present.
func (s *Session) GetTokens(asIssuer string) (*TokenEntry, bool) {
	e, ok := s.Tokens[asIssuer]
	return e, ok
}

// Authenticated reports whether the login completed (identity captured).
func (s *Session) Authenticated() bool { return len(s.Identity) > 0 }

// sessionStore persists sessions in a kv.Store: the record under "pep:session:<id>" plus a
// "pep:state:<state>" index → id. Each save refreshes the TTL (sliding expiry); the record + index are
// written in one atomic SetMany so a state lookup never resolves a half-written record.
type sessionStore struct {
	store       kv.Store
	ttl         time.Duration // idle timeout (sliding)
	maxLifetime time.Duration // absolute timeout from CreatedAt
	stateTTL    time.Duration // login-window TTL for the state index
}

func newSessionStore(store kv.Store, ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &sessionStore{store: store, ttl: ttl, maxLifetime: defaultSessionMaxLifetime, stateTTL: defaultStateTTL}
}

func sessionKey(id string) string  { return "pep:session:" + id }
func stateKey(state string) string { return "pep:state:" + state }

func (m *sessionStore) create() *Session {
	return &Session{ID: ksuid.New().String(), CreatedAt: time.Now()}
}

// rotate gives the session a fresh id, persists it under the new id, and deletes the old record — called on
// successful authentication (anti session-fixation) by whichever device holds the cookie. CreatedAt is
// preserved, so the absolute lifetime cap still counts from the original login start.
func (m *sessionStore) rotate(s *Session) error {
	oldID := s.ID
	s.ID = ksuid.New().String()
	if err := m.save(s); err != nil {
		s.ID = oldID
		return err
	}
	_ = m.store.Delete(context.Background(), sessionKey(oldID))
	return nil
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
		entries = append(entries, kv.Entry{Key: stateKey(s.State), Value: idValue, TTL: m.stateTTL})
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
	// Absolute timeout: a session past its max lifetime is treated as absent and garbage-collected on access,
	// regardless of how recently the sliding idle TTL was refreshed.
	if m.maxLifetime > 0 && !s.CreatedAt.IsZero() && time.Since(s.CreatedAt) > m.maxLifetime {
		ctx := context.Background()
		_ = m.store.Delete(ctx, sessionKey(id))
		if s.State != "" {
			_ = m.store.Delete(ctx, stateKey(s.State))
		}
		return nil, fmt.Errorf("session %q expired (max lifetime)", id)
	}
	return &s, nil
}

// deleteState consumes a one-time login state: it removes the pep:state index so the same OAuth state
// cannot be replayed after the callback has used it.
func (m *sessionStore) deleteState(state string) {
	if state != "" {
		_ = m.store.Delete(context.Background(), stateKey(state))
	}
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
