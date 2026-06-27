package authzserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// kvSessionStore implements AuthzServerSessionStore over a kv.Store. The session record lives under
// "as:session:<id>"; secondary lookups (state, code, authn-state, request_uri) are index keys holding
// the id. Save writes the record + all populated index keys atomically (SetMany), so a lookup never
// resolves a half-written session. GetByCode consumes the code index (Take) so an authorization code is
// single-use even under concurrent token requests.
type kvSessionStore struct {
	store      kv.Store
	defaultTTL time.Duration
}

func newKVSessionStore(store kv.Store, defaultTTL time.Duration) *kvSessionStore {
	return &kvSessionStore{store: store, defaultTTL: defaultTTL}
}

var errSessionNotFound = errors.New("session not found")

func asSessionKey(id string) string      { return "as:session:" + id }
func asStateKey(state string) string     { return "as:state:" + state }
func asCodeKey(code string) string       { return "as:code:" + code }
func asAuthnKey(state string) string     { return "as:authn:" + state }
func asRequriKey(uri string) string      { return "as:requri:" + uri }
func asRefreshKey(token string) string   { return "as:refresh:" + token }

// ttl bounds how long a session (and its index keys) live: until ExpiresAt when set, otherwise the
// default (the pending window between /auth and /token, before a policy sets ExpiresAt).
func (s *kvSessionStore) ttl(sess *AuthzServerSession) time.Duration {
	if !sess.ExpiresAt.IsZero() {
		if d := time.Until(sess.ExpiresAt); d > 0 {
			return d
		}
		return time.Second
	}
	return s.defaultTTL
}

func (s *kvSessionStore) SaveAutzhServerSession(session *AuthzServerSession) error {
	ctx := context.Background()
	record, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	idValue, err := json.Marshal(session.ID)
	if err != nil {
		return err
	}
	ttl := s.ttl(session)

	entries := []kv.Entry{{Key: asSessionKey(session.ID), Value: record, TTL: ttl}}
	addIndex := func(key string) { entries = append(entries, kv.Entry{Key: key, Value: idValue, TTL: ttl}) }
	if session.State != "" {
		addIndex(asStateKey(session.State))
	}
	if session.Code != "" {
		addIndex(asCodeKey(session.Code))
	}
	if session.AuthnClientSession != nil && session.AuthnClientSession.State != "" {
		addIndex(asAuthnKey(session.AuthnClientSession.State))
	}
	if session.RequestUri != "" {
		addIndex(asRequriKey(session.RequestUri))
	}
	if session.RefreshToken != "" {
		addIndex(asRefreshKey(session.RefreshToken))
	}
	return s.store.SetMany(ctx, entries...)
}

func (s *kvSessionStore) GetAuthzServerSessionByID(id string) (*AuthzServerSession, error) {
	data, found, err := s.store.Get(context.Background(), asSessionKey(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errSessionNotFound
	}
	var sess AuthzServerSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &sess, nil
}

// resolveIndex reads an index key (holding a session id) and returns the referenced session.
func (s *kvSessionStore) resolveIndex(idData []byte, found bool, err error) (*AuthzServerSession, error) {
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errSessionNotFound
	}
	var id string
	if err := json.Unmarshal(idData, &id); err != nil {
		return nil, err
	}
	return s.GetAuthzServerSessionByID(id)
}

func (s *kvSessionStore) GetAuthzServerSessionByState(state string) (*AuthzServerSession, error) {
	v, found, err := s.store.Get(context.Background(), asStateKey(state))
	return s.resolveIndex(v, found, err)
}

func (s *kvSessionStore) GetAuthzServerSessionByAuthnState(authnState string) (*AuthzServerSession, error) {
	v, found, err := s.store.Get(context.Background(), asAuthnKey(authnState))
	return s.resolveIndex(v, found, err)
}

func (s *kvSessionStore) GetAutzhServerSessionByRequestURI(requestURI string) (*AuthzServerSession, error) {
	v, found, err := s.store.Get(context.Background(), asRequriKey(requestURI))
	return s.resolveIndex(v, found, err)
}

func (s *kvSessionStore) GetAuthzServerSessionByRefreshToken(token string) (*AuthzServerSession, error) {
	v, found, err := s.store.Get(context.Background(), asRefreshKey(token))
	return s.resolveIndex(v, found, err)
}

// GetAuthzServerSessionByCode consumes the code index (Take) so an authorization code is single-use
// (RFC 6749 §4.1.2): a concurrent or replayed exchange of the same code resolves to not-found.
func (s *kvSessionStore) GetAuthzServerSessionByCode(code string) (*AuthzServerSession, error) {
	v, found, err := s.store.Take(context.Background(), asCodeKey(code))
	return s.resolveIndex(v, found, err)
}

func (s *kvSessionStore) DeleteAuthzServerSessionByID(id string) error {
	ctx := context.Background()
	sess, err := s.GetAuthzServerSessionByID(id)
	if err != nil {
		// Nothing to delete (or already gone); drop the record key just in case.
		_ = s.store.Delete(ctx, asSessionKey(id))
		return err
	}
	_ = s.store.Delete(ctx, asSessionKey(id))
	if sess.State != "" {
		_ = s.store.Delete(ctx, asStateKey(sess.State))
	}
	if sess.Code != "" {
		_ = s.store.Delete(ctx, asCodeKey(sess.Code))
	}
	if sess.AuthnClientSession != nil && sess.AuthnClientSession.State != "" {
		_ = s.store.Delete(ctx, asAuthnKey(sess.AuthnClientSession.State))
	}
	if sess.RequestUri != "" {
		_ = s.store.Delete(ctx, asRequriKey(sess.RequestUri))
	}
	return nil
}
