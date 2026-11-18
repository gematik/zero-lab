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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"
)

const (
	// defaultSessionTTL is the idle timeout: each save refreshes it (sliding expiry).
	defaultSessionTTL = time.Hour
	// defaultSessionMaxLifetime is the absolute cap from creation, enforced regardless of activity, so an
	// actively-used session cannot live forever (OWASP: both idle and absolute timeouts).
	defaultSessionMaxLifetime = 12 * time.Hour
)

// LoginStateTTL is how long a [SessionStore] keeps the index from a login's state to its session: the login
// window, so an abandoned login's state expires quickly instead of lingering for the whole session.
const LoginStateTTL = 15 * time.Minute

// Session is the server-side login session. The browser holds an opaque, HttpOnly cookie carrying a random
// secret token; the record is stored under ID = hashToken(token), so reading the store (a rogue storage
// admin) reveals only hashes, never a usable cookie. Tokens and identity stay here (the BCP token-mediating
// property). IDPIss records which provider the login is/was driven against so the callback resolves the
// same client.
type Session struct {
	// token is the cookie secret. It is set on create/rotate, written to the cookie, and never persisted
	// (unexported ⇒ not marshaled); the store's key is its hash. Empty on sessions loaded from the store.
	token string

	ID                   string         `json:"id"`
	IDPIss               string         `json:"idp_iss,omitempty"`
	State                string         `json:"state"`
	Nonce                string         `json:"nonce"`
	CodeVerifier         string         `json:"code_verifier"`
	CodeChallengeMethod  string         `json:"code_challenge_method"`
	AccessToken          string         `json:"access_token,omitempty"`
	RefreshToken         string         `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt time.Time      `json:"access_token_expires_at"`
	Identity             map[string]any `json:"identity,omitempty"`
	ReturnTo             string         `json:"return_to,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	// LoginMode is LoginStart.Mode of the login this session began, which decides who may complete it at the
	// callback (crossDevice). Empty, as on a session stored before it was recorded, is the redirect rule.
	LoginMode string `json:"login_mode,omitempty"`

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
	ExpiresAt    time.Time `json:"expires_at"`
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

// ErrSessionNotFound is what a [SessionStore] returns for a session or a login state it does not hold, or no
// longer holds.
var ErrSessionNotFound = errors.New("session not found")

// SessionStore keeps the sessions of all replicas. The proxy treats any error from it as an absent session, so
// the user logs in again; a record that fails the store's integrity check is reported by the store, at error
// level, since only the store can tell it apart (server rule 14). A persistent store holds ciphertext only
// (server rule 5).
type SessionStore interface {
	// Save keeps the session for ttl, which every save starts again, and, when its State is set, an index from
	// that state to its ID for [LoginStateTTL]. Both are written at once, so a lookup by state never resolves a
	// half-written session. The state is a secret, kept out of anything stored in the clear (server rule 10).
	Save(ctx context.Context, s *Session, ttl time.Duration) error
	// Load returns the session stored under id, or [ErrSessionNotFound].
	Load(ctx context.Context, id string) (*Session, error)
	// SessionID returns the ID of the session whose login has state, or [ErrSessionNotFound].
	SessionID(ctx context.Context, state string) (string, error)
	// Delete removes the session stored under id, and DeleteState the index of state; what is gone already is
	// no error.
	Delete(ctx context.Context, id string) error
	DeleteState(ctx context.Context, state string) error
}

// sessionManager holds the proxy's rules for sessions over a [SessionStore]: their IDs, rotation, and the idle
// and absolute timeouts.
type sessionManager struct {
	store       SessionStore
	ttl         time.Duration // idle timeout (sliding)
	maxLifetime time.Duration // absolute timeout from CreatedAt
	now         func() time.Time
	log         *slog.Logger
}

func newSessionManager(store SessionStore, ttl time.Duration, log *slog.Logger) *sessionManager {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &sessionManager{now: time.Now, store: store, ttl: ttl, maxLifetime: defaultSessionMaxLifetime, log: log}
}

// errSessionMismatch is a record that names another session than the one it was stored under.
var errSessionMismatch = errors.New("session record names another session")

func (m *sessionManager) create() *Session {
	token := randomToken()
	return &Session{token: token, ID: hashToken(token), CreatedAt: m.now()}
}

// rotate gives the session a fresh token + id, persists it under the new id, and deletes the old record —
// called on successful authentication (anti session-fixation) by whichever device holds the cookie. The
// caller must re-set the cookie to the new token. CreatedAt is preserved, so the absolute lifetime cap still
// counts from the original login start.
func (m *sessionManager) rotate(ctx context.Context, s *Session) error {
	oldID := s.ID
	token := randomToken()
	s.token = token
	s.ID = hashToken(token)
	if err := m.save(ctx, s); err != nil {
		s.ID, s.token = oldID, ""
		return err
	}
	_ = m.store.Delete(context.WithoutCancel(ctx), oldID)
	return nil
}

// byToken resolves the session for a cookie token by hashing it to the store's key. The token is never stored,
// so a rogue storage admin reading the store learns only hashes and cannot reconstruct a valid cookie.
func (m *sessionManager) byToken(ctx context.Context, token string) (*Session, error) {
	return m.byID(ctx, hashToken(token))
}

// logRef is what a log says for a session: enough to correlate its lines, and nothing of its ID, which names the
// session's record and revocation entry (server rule 5). An empty ID has no reference.
func logRef(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}

// hashToken maps a cookie secret to its session ID (SHA-256, base64url).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomToken returns a 256-bit random cookie secret.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *sessionManager) save(ctx context.Context, s *Session) error {
	return m.store.Save(ctx, s, m.ttl)
}

func (m *sessionManager) byID(ctx context.Context, id string) (*Session, error) {
	s, err := m.store.Load(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.ID != id {
		// Defense in depth (a sealed store already binds record and key): never serve a record whose own id
		// differs from the slot it was read from. It can mean tampering with the store (server rule 14).
		m.log.Error("session record names another session, treating it as absent")
		return nil, errSessionMismatch
	}
	// Absolute timeout: a session past its max lifetime is treated as absent and garbage-collected on access,
	// regardless of how recently the sliding idle TTL was refreshed.
	if m.maxLifetime > 0 && !s.CreatedAt.IsZero() && m.now().Sub(s.CreatedAt) > m.maxLifetime {
		m.remove(ctx, s)
		return nil, errors.New("session expired (max lifetime)")
	}
	return s, nil
}

// remove deletes a session and its state index. It runs to the end when the request is cancelled, so no part
// of an ended session stays behind.
func (m *sessionManager) remove(ctx context.Context, s *Session) {
	ctx = context.WithoutCancel(ctx)
	_ = m.store.Delete(ctx, s.ID)
	if s.State != "" {
		_ = m.store.DeleteState(ctx, s.State)
	}
}

// deleteState consumes a one-time login state: it removes the state index so the same OAuth state cannot be
// replayed after the callback has used it.
func (m *sessionManager) deleteState(ctx context.Context, state string) {
	if state != "" {
		_ = m.store.DeleteState(context.WithoutCancel(ctx), state)
	}
}

func (m *sessionManager) byState(ctx context.Context, state string) (*Session, error) {
	id, err := m.store.SessionID(ctx, state)
	if err != nil {
		return nil, err
	}
	return m.byID(ctx, id)
}

func (m *sessionManager) deleteByID(ctx context.Context, id string) error {
	s, err := m.byID(ctx, id)
	if err != nil {
		return err
	}
	m.remove(ctx, s)
	return nil
}
