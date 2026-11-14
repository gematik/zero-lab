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

package authzserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/nonce"
)

// The interfaces are met by shape, so that the modules need not import each other; this is where that holds.
var _ dpop.NonceSource = (*nonce.Source)(nil)

// memorySessions is a SessionStore in the memory of the test: lookups by authentication state, request_uri
// and code consume them, as the interface requires. Records are copied in and out, as a store does.
type memorySessions struct {
	mu       sync.Mutex
	records  map[string]memorySession
	authn    map[string]string
	requests map[string]string
	codes    map[string]string
	refresh  map[string]string
}

type memorySession struct {
	record  []byte
	expires time.Time
}

func newMemorySessions() *memorySessions {
	return &memorySessions{
		records:  map[string]memorySession{},
		authn:    map[string]string{},
		requests: map[string]string{},
		codes:    map[string]string{},
		refresh:  map[string]string{},
	}
}

func (m *memorySessions) SaveAutzhServerSession(session *Session) error {
	record, err := json.Marshal(session) //nolint:gosec // the record stays in the memory of the test, as a store would hold it
	if err != nil {
		return err
	}
	expires := session.ExpiresAt
	if expires.IsZero() {
		expires = time.Now().Add(DefaultSessionTTL)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[session.ID] = memorySession{record: record, expires: expires}
	if session.Code != "" {
		m.codes[session.Code] = session.ID
	}
	if session.RequestURI != "" {
		m.requests[session.RequestURI] = session.ID
	}
	if session.RefreshToken != "" {
		m.refresh[session.RefreshToken] = session.ID
	}
	if session.AuthnClientSession != nil && session.AuthnClientSession.State != "" {
		m.authn[session.AuthnClientSession.State] = session.ID
	}
	return nil
}

// byID is GetAuthzServerSessionByID with the lock held.
func (m *memorySessions) byID(id string) (*Session, error) {
	stored, ok := m.records[id]
	if !ok || !time.Now().Before(stored.expires) {
		return nil, ErrSessionNotFound
	}
	var session Session
	if err := json.Unmarshal(stored.record, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (m *memorySessions) lookup(index map[string]string, value string, consume bool) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := index[value]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if consume {
		delete(index, value)
	}
	return m.byID(id)
}

func (m *memorySessions) GetAuthzServerSessionByID(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byID(id)
}

func (m *memorySessions) GetAuthzServerSessionByAuthnState(state string) (*Session, error) {
	return m.lookup(m.authn, state, true)
}

func (m *memorySessions) GetAutzhServerSessionByRequestURI(requestURI string) (*Session, error) {
	return m.lookup(m.requests, requestURI, true)
}

func (m *memorySessions) GetAuthzServerSessionByCode(code string) (*Session, error) {
	return m.lookup(m.codes, code, true)
}

func (m *memorySessions) GetAuthzServerSessionByRefreshToken(token string) (*Session, error) {
	return m.lookup(m.refresh, token, false)
}

// peekAuthnState reads a pending login's session without consuming its state, as the callback does.
func (m *memorySessions) peekAuthnState(state string) (*Session, error) {
	return m.lookup(m.authn, state, false)
}

func (m *memorySessions) DeleteRefreshIndex(refreshTokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refresh, refreshTokenHash)
	return nil
}

func (m *memorySessions) DeleteAuthzServerSessionByID(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, err := m.byID(id)
	delete(m.records, id)
	if err != nil {
		return err
	}
	delete(m.codes, session.Code)
	delete(m.requests, session.RequestURI)
	delete(m.refresh, session.RefreshToken)
	if session.AuthnClientSession != nil {
		delete(m.authn, session.AuthnClientSession.State)
	}
	return nil
}

// memoryRedemptions are nonce.Redemptions in the memory of the test.
type memoryRedemptions struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newMemoryRedemptions() *memoryRedemptions {
	return &memoryRedemptions{seen: map[string]time.Time{}}
}

func (m *memoryRedemptions) Seen(_ context.Context, id string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if expiry, ok := m.seen[id]; ok && time.Now().Before(expiry) {
		return true, nil
	}
	m.seen[id] = until
	return false, nil
}

// testStores are the state replicas share; servers built with the same testStores are replicas of each other.
type testStores struct {
	sessions    *memorySessions
	redemptions nonce.Redemptions
	replays     dpop.Replays
	keys        nonce.Keys
}

func newTestStores(t *testing.T) *testStores {
	t.Helper()
	return &testStores{
		sessions:    newMemorySessions(),
		redemptions: newMemoryRedemptions(),
		replays:     dpop.NewMemoryReplays(1000, nil),
		keys:        testNonceKeys(t),
	}
}

// with returns cfg with the stores in it.
func (s *testStores) with(cfg Config) Config {
	cfg.Sessions, cfg.NonceRedemptions, cfg.Replays, cfg.NonceKeys = s.sessions, s.redemptions, s.replays, s.keys
	return cfg
}

// withTestStores returns cfg with stores of its own, for a test of one server.
func withTestStores(t *testing.T, cfg Config) Config {
	t.Helper()
	return newTestStores(t).with(cfg)
}

func testNonceKeys(t *testing.T) nonce.Keys {
	t.Helper()
	keys, err := nonce.NewEphemeralKeys()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// replicas builds two servers that share stores and keys, as replicas behind one endpoint do.
func replicas(t *testing.T, stores *testStores) (a, b *Server, signKey *jose.JSONWebKey) {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signKey = &jose.JSONWebKey{Key: prk, KeyID: "test-client-key"}
	pubKey := signKey.Public()
	signer := newP256(t)
	build := func() *Server {
		server, err := New(stores.with(Config{
			Issuer:     testIssuer,
			SigningKey: &SigningKey{Signer: signer, KeyID: "test-server-key"},
			Products: []Product{{
				ProductID:    testProductID,
				RedirectURIs: []string{"https://rp.example.com/callback"},
				Scopes:       []string{testScope},
			}},
			Clients: []Client{{ClientID: testClientID, ProductID: testProductID, PublicJWK: jwkToMap(t, &pubKey)}},
		}))
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	return build(), build(), signKey
}

func requireStatus(t *testing.T, err error, status int, code string) {
	t.Helper()
	var authzErr *Error
	if !errors.As(err, &authzErr) || authzErr.HTTPStatus != status || authzErr.Code != code {
		t.Fatalf("got %v, want %d %s", err, status, code)
	}
}

// Server rule 17: without its stores the server would keep sessions, nonces and proofs in its own memory, where
// no other replica sees them; it refuses to start and names what is missing.
func TestServerRule17_NewRefusesAConfigurationWithoutItsStores(t *testing.T) {
	for name, drop := range map[string]func(*Config){
		"Sessions":         func(c *Config) { c.Sessions = nil },
		"NonceRedemptions": func(c *Config) { c.NonceRedemptions = nil },
		"Replays":          func(c *Config) { c.Replays = nil },
		"NonceKeys":        func(c *Config) { c.NonceKeys = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := withTestStores(t, Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: newP256(t), KeyID: "k"}})
			drop(&cfg)
			_, err := New(cfg)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A nonce issued at one replica is good at another, and single use holds across them.
func TestServerRule11_PrivateKeyJWTNonceIsAcceptedOnceAcrossReplicas(t *testing.T) {
	a, b, signKey := replicas(t, newTestStores(t))
	assertion := signClientAssertion(t, a, signKey, nil)
	if err := b.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion)); err != nil {
		t.Fatalf("redeeming at the other replica: %v", err)
	}
	assertInvalidClient(t, a.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion)))
}

// RFC 9449 Section 11.1: a proof accepted at one replica is refused at another.
func TestRFC9449_11_1_ProofReplayedAtAnotherReplicaIsRefused(t *testing.T) {
	a, b, signKey := replicas(t, newTestStores(t))
	proofed := clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil))
	if err := a.TokenEndpoint(httptest.NewRecorder(), proofed); err != nil {
		t.Fatalf("first use: %v", err)
	}
	replay := clientCredentialsRequestWithProof(t, signClientAssertion(t, a, signKey, nil), nil)
	replay.Header.Set(dpop.HeaderName, proofed.Header.Get(dpop.HeaderName))
	err := b.TokenEndpoint(httptest.NewRecorder(), replay)
	requireStatus(t, err, http.StatusBadRequest, "invalid_dpop_proof")
	if !strings.Contains(err.Error(), "used before") {
		t.Fatalf("refused for another reason: %v", err)
	}
}

// errOutage is a store outage, with a detail no client may read.
var errOutage = errors.New("kv/postgres: store down, secret detail")

// failing are Replays and Redemptions on a store that is down.
type failing struct{}

func (failing) Seen(context.Context, string, time.Time) (bool, error) { return false, errOutage }

// Server rule 16: an outage of the store behind single use means deny, and its text stays out of the answer.
func TestServerRule16_ANonceStoreOutageFailsClosedAndLeaksNothing(t *testing.T) {
	stores := newTestStores(t)
	stores.redemptions = failing{}
	a, _, signKey := replicas(t, stores)
	err := a.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil)))
	requireStatus(t, err, http.StatusInternalServerError, "server_error")
	if strings.Contains(err.Error(), "secret detail") {
		t.Fatalf("the response carries the store's error: %v", err)
	}
}

// Server rule 16: without the replays no proof is accepted.
func TestServerRule16_ADPoPReplaysOutageRefusesTheProof(t *testing.T) {
	stores := newTestStores(t)
	stores.replays = failing{}
	a, _, signKey := replicas(t, stores)
	resp := httptest.NewRecorder()
	err := a.TokenEndpoint(resp, clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil)))
	requireStatus(t, err, http.StatusInternalServerError, "server_error")
	if resp.Code == http.StatusOK && resp.Body.Len() > 0 {
		t.Fatal("tokens were issued")
	}
}

// countingSeen counts the calls to Replays or Redemptions.
type countingSeen struct {
	inner interface {
		Seen(ctx context.Context, id string, until time.Time) (bool, error)
	}
	writes *atomic.Int64
}

func (c countingSeen) Seen(ctx context.Context, id string, until time.Time) (bool, error) {
	c.writes.Add(1)
	return c.inner.Seen(ctx, id, until)
}

// countingSessions counts the sessions saved.
type countingSessions struct {
	*memorySessions
	writes *atomic.Int64
}

func (s countingSessions) SaveAutzhServerSession(session *Session) error {
	s.writes.Add(1)
	return s.memorySessions.SaveAutzhServerSession(session)
}

// Server rule 10: handing out a nonce costs no store.
func TestServerRule10_AnAnonymousNonceRequestCausesNoWrite(t *testing.T) {
	var writes atomic.Int64
	stores := newTestStores(t)
	stores.redemptions = countingSeen{inner: stores.redemptions, writes: &writes}
	stores.replays = countingSeen{inner: stores.replays, writes: &writes}
	cfg := stores.with(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: newP256(t), KeyID: "k"}})
	cfg.Sessions = countingSessions{memorySessions: stores.sessions, writes: &writes}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	if err := a.NonceEndpoint(resp, httptest.NewRequest(http.MethodGet, testIssuer+"/nonce", nil)); err != nil {
		t.Fatal(err)
	}
	if resp.Code != http.StatusOK || resp.Body.Len() == 0 {
		t.Fatalf("status %d, %q", resp.Code, resp.Body)
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("%d writes", n)
	}
}

// RFC 9449 Section 8 stays possible on the same keys: a proof must carry a nonce from the source, and one
// issued at another replica counts. nonce_required itself is TASK-131.
func TestRFC9449_8_ASourceOnTheNonceKeysServesAVerifier(t *testing.T) {
	keys := testNonceKeys(t)
	source, err := nonce.NewSource(keys, "pep/dpop-nonce", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := dpop.NewVerifier(dpop.Config{Nonces: source})
	if err != nil {
		t.Fatal(err)
	}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	req := dpop.Request{Method: http.MethodPost, URI: testIssuer + "/token"}
	withNonce := func(value string) http.Header {
		proof, err := key.Proof(req.Method, req.URI, dpop.ProofOptions{Nonce: value})
		if err != nil {
			t.Fatal(err)
		}
		header := http.Header{}
		header.Set(dpop.HeaderName, proof)
		return header
	}
	if _, err := verifier.Verify(t.Context(), withNonce(""), req); err == nil {
		t.Fatal("accepted a proof without a nonce")
	}
	fresh, err := source.Fresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), withNonce(fresh), req); err != nil {
		t.Fatalf("refused the source's nonce: %v", err)
	}
}

// Server rule 10: the session store only ever receives the hash of a refresh token; the raw token goes to the
// client alone, so a reader of the store holds nothing it could redeem.
func TestServerRule10_TheStoreReceivesOnlyTheHashOfARefreshToken(t *testing.T) {
	s, _ := newTestServer(t)
	session := &Session{ID: "session-1", ClientID: testClientID, AccessTokenDuration: time.Minute, ExpiresAt: time.Now().Add(time.Hour)}
	response, err := s.issueOrRefreshTokens(session)
	if err != nil {
		t.Fatal(err)
	}
	if response.RefreshToken == "" || session.RefreshToken == response.RefreshToken {
		t.Fatalf("the session to be stored holds the raw refresh token")
	}
	if session.RefreshToken != hashRefreshToken(response.RefreshToken) {
		t.Errorf("the session holds %q, not the hash of the issued token", session.RefreshToken)
	}
}
