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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/openid/providers"
)

const (
	testOPIssuer = "https://op.example"
	// testCodeVerifier is the RFC 7636 appendix B verifier of testCodeChallenge.
	testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// testInternals stands for what an error may carry that no client may read.
	testInternals = "internals-value"
)

// fakeOP is an upstream OpenID provider that does what its fields say.
type fakeOP struct {
	authErr     error
	exchangeErr error
	login       openid.Login
}

func (f *fakeOP) Issuer() string { return testOPIssuer }

func (f *fakeOP) AuthenticationURL(_ context.Context, login openid.Login) (string, error) {
	if f.authErr != nil {
		return "", f.authErr
	}
	f.login = login
	return testOPIssuer + "/auth?" + url.Values{"state": {login.State}, "nonce": {login.Nonce}}.Encode(), nil
}

func (f *fakeOP) Exchange(_ context.Context, _ openid.Login, _ string) (*openid.TokenResponse, error) {
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"nonce":%q}`, f.login.Nonce))
	return &openid.TokenResponse{AccessToken: "op-access-token-value", RefreshToken: "op-refresh-token-value", IDTokenRaw: "e30." + payload + ".sig"}, nil
}

func captureDebugLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// pendingLogin runs the pushed request and the redirect to the provider, as a client and a browser do, and returns
// the state the provider has to send back.
func pendingLogin(t *testing.T, server *Server, assertion string, op *fakeOP) (opState string) {
	t.Helper()
	server.providers.Add(providers.Provider{Issuer: testOPIssuer, Client: op})
	server.defaultIDPIss = testOPIssuer

	pushed := httptest.NewRecorder()
	server.handle(server.PAREndpoint).ServeHTTP(pushed, parRequest(assertion))
	if pushed.Code != http.StatusCreated {
		t.Fatalf("PAR = %d: %s", pushed.Code, pushed.Body)
	}
	var par struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &par); err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRecorder()
	server.handle(server.AuthorizationEndpoint).ServeHTTP(authorize, httptest.NewRequest(http.MethodGet, "/auth?"+url.Values{"request_uri": {par.RequestURI}}.Encode(), nil))
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", authorize.Code, authorize.Body)
	}
	return op.login.State
}

// sessionOfState reads a pending login's session without consuming its state, as the callback does.
func sessionOfState(t *testing.T, server *Server, opState string) *Session {
	t.Helper()
	store, ok := server.sessionStore.(*kvSessionStore)
	if !ok {
		t.Fatalf("session store is a %T", server.sessionStore)
	}
	data, found, err := store.store.Get(context.Background(), asAuthnKey(opState))
	if err != nil || !found {
		t.Fatalf("no index for the state: %v", err)
	}
	session, err := store.resolveIndex(data, found, nil)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func callback(server *Server, query url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	server.handle(server.OPCallbackEndpoint).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/op-callback?"+query.Encode(), nil))
	return rec
}

func authorizationCodeRequest(t *testing.T, assertion, code string) *http.Request {
	t.Helper()
	form := url.Values{
		"grant_type":            {GrantTypeAuthorizationCode},
		"code":                  {code},
		"code_verifier":         {testCodeVerifier},
		"redirect_uri":          {"https://rp.example.com/callback"},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
	}
	request := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := testDPoPKey.Sign(request, dpop.ProofOptions{}); err != nil {
		t.Fatal(err)
	}
	return request
}

func assertNoneInLog(t *testing.T, logs *bytes.Buffer, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs)
		}
	}
}

// Server rules 5 and 14: the whole login, from the pushed request to the tokens, in the callback's case the path
// that once logged both sessions.
func TestServerRule14_ALoginLogsNoSecretAtDebug(t *testing.T) {
	logs := captureDebugLogs(t)
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	parAssertion := signClientAssertion(t, server, signKey, nil)
	opState := pendingLogin(t, server, parAssertion, op)
	session := sessionOfState(t, server, opState)

	const opCode = "op-code-value"
	done := callback(server, url.Values{"state": {opState}, "code": {opCode}})
	if done.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", done.Code, done.Body)
	}
	location, err := url.Parse(done.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	clientCode := location.Query().Get("code")

	assertion := signClientAssertion(t, server, signKey, nil)
	issued := httptest.NewRecorder()
	server.handle(server.TokenEndpoint).ServeHTTP(issued, authorizationCodeRequest(t, assertion, clientCode))
	if issued.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", issued.Code, issued.Body)
	}
	var tokens TokenResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(logs.String(), "tokens issued") {
		t.Fatalf("the login went unlogged:\n%s", logs)
	}
	assertNoneInLog(t, logs, parAssertion, assertion, "st-123", testCodeChallenge, testCodeVerifier,
		session.ID, session.RequestURI, session.AuthnClientSession.ID,
		op.login.State, op.login.Nonce, op.login.Verifier, opCode, "op-access-token-value", "op-refresh-token-value",
		clientCode, tokens.AccessToken, tokens.RefreshToken)
}

// An upstream's refusal is outside this server's control and may echo what it was sent.
func TestServerRule14_ALoginThatFailsLogsNoSecretEvenIfTheProviderEchoesIt(t *testing.T) {
	logs := captureDebugLogs(t)
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
	const opCode = "op-code-value"
	op.exchangeErr = fmt.Errorf("no such code %s, verifier %s", opCode, op.login.Verifier)
	if rec := callback(server, url.Values{"state": {opState}, "code": {opCode}}); rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "no such code") {
		t.Errorf("the detail is gone from the log:\n%s", logs)
	}
	assertNoneInLog(t, logs, opState, op.login.Nonce, op.login.Verifier, opCode)
}

// Server rule 10: a kv key is in clear even in a sealed store, so it holds a hash of a secret.
func TestServerRule10_AKVKeyHoldsNoSecretOfALogin(t *testing.T) {
	server, signKey := newTestServer(t)
	memory := kv.NewMemory()
	server.sessionStore = newKVSessionStore(memory, time.Hour)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
	session := sessionOfState(t, server, opState)
	requestURI := session.RequestURI
	done := callback(server, url.Values{"state": {opState}, "code": {"op-code-value"}})
	location, err := url.Parse(done.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	clientCode := location.Query().Get("code")
	if clientCode == "" {
		t.Fatalf("no code: %s", done.Header().Get("Location"))
	}
	keys, err := memory.Keys(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("no keys to check")
	}
	for _, key := range keys {
		for name, secret := range map[string]string{"code": clientCode, "state": opState, "request_uri": requestURI} {
			if secret != "" && strings.Contains(key, secret) {
				t.Errorf("key %q holds the %s", key, name)
			}
		}
	}
	if len(keysWithPrefix(keys, "as:code:")) != 1 {
		t.Errorf("keys = %v", keys)
	}
}

func keysWithPrefix(keys []string, prefix string) []string {
	var found []string
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			found = append(found, key)
		}
	}
	return found
}

// RFC 9700 section 2.1 (RFC 6749 section 10.12): a state answers one request. A replay with another code must not overwrite the authorization
// code the first callback issued, also after the session was saved again.
func TestRFC9700_2_1_TheStateOfAnOPCallbackIsSingleUse(t *testing.T) {
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)

	first := callback(server, url.Values{"state": {opState}, "code": {"op-code-value"}})
	if first.Code != http.StatusFound {
		t.Fatalf("first callback = %d: %s", first.Code, first.Body)
	}
	location, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	clientCode := location.Query().Get("code")

	replay := callback(server, url.Values{"state": {opState}, "code": {"attacker-code-value"}})
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay = %d: %s", replay.Code, replay.Body)
	}

	issued := httptest.NewRecorder()
	assertion := signClientAssertion(t, server, signKey, nil)
	server.handle(server.TokenEndpoint).ServeHTTP(issued, authorizationCodeRequest(t, assertion, clientCode))
	if issued.Code != http.StatusOK {
		t.Fatalf("the first callback's code stopped working: %d: %s", issued.Code, issued.Body)
	}
}

// A request that is no answer of the provider does not end the login it names.
func TestOPCallback_ARequestWithoutACodeDoesNotConsumeTheState(t *testing.T) {
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
	if rec := callback(server, url.Values{"state": {opState}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no code = %d: %s", rec.Code, rec.Body)
	}
	if rec := callback(server, url.Values{"state": {opState}, "code": {"op-code-value"}}); rec.Code != http.StatusFound {
		t.Fatalf("the login did not survive: %d: %s", rec.Code, rec.Body)
	}
}

// RFC 6749 section 4.1.2.1: a login that fails after the client is known ends at the client, not in JSON in the browser.
func TestRFC6749_4_1_2_1_AFailedLoginRedirectsToTheClientWithGenericText(t *testing.T) {
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
	op.exchangeErr = errors.New(testInternals)
	rec := callback(server, url.Values{"state": {opState}, "code": {"c"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != "https://rp.example.com/callback" {
		t.Errorf("redirected to %s", got)
	}
	query := location.Query()
	if query.Get("state") != "st-123" || query.Get("error") != "server_error" {
		t.Errorf("query = %v", query)
	}
	if strings.Contains(rec.Header().Get("Location"), testInternals) {
		t.Errorf("internals reached the client: %s", rec.Header().Get("Location"))
	}
}

// An unknown client and a bad signature read alike, so the answer does not say which clients exist.
func TestServerRule2_ClientVerificationFailuresNameNoDetail(t *testing.T) {
	server, signKey := newTestServer(t)
	assertion := signClientAssertion(t, server, signKey, nil)
	request := func(assertion string) *http.Request {
		form := url.Values{"client_assertion_type": {ClientAssertionTypeJWTBearer}, "client_assertion": {assertion}}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	unknown := signClientAssertion(t, server, signKey, func(claims map[string]any) {
		claims["iss"], claims["sub"] = "unknown-client", "unknown-client"
	})
	parts := strings.Split(assertion, ".")
	for name, value := range map[string]string{
		"not a token":     "not-a-token",
		"unknown client":  unknown,
		"wrong signature": parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, failure := server.verifyClient(request(value))
			if failure == nil {
				t.Fatal("accepted")
			}
			if failure.Code != "invalid_client" || failure.Description != clientAuthFailed {
				t.Errorf("answer = %s: %s", failure.Code, failure.Description)
			}
		})
	}
}

// RFC 6749 section 4.1.2.1: the error goes to the client's redirect URI with the client's state. The session's other
// ones are the server's own callback at the provider and the state it sent there.
func TestRFC6749_4_1_2_1_AnUpstreamErrorReachesTheClientWithItsOwnState(t *testing.T) {
	server, signKey := newTestServer(t)
	op := &fakeOP{}
	opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
	rec := callback(server, url.Values{"state": {opState}, "error": {"access_denied"}, "error_description": {"the user said no"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != "https://rp.example.com/callback" {
		t.Errorf("redirected to %s", got)
	}
	query := location.Query()
	if query.Get("state") != "st-123" || query.Get("error") != "access_denied" || query.Get("error_description") != "the user said no" {
		t.Errorf("query = %v", query)
	}
}

// failingStore fails as the Postgres store used to, naming the key.
type failingStore struct {
	kv.Store
	fail map[string]bool
}

func (s *failingStore) refusal(operation, key string) error {
	return fmt.Errorf("kv/postgres: %s %q: %s", operation, key, testInternals)
}

func (s *failingStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if s.fail["get"] {
		return nil, false, s.refusal("get", key)
	}
	return s.Store.Get(ctx, key)
}

func (s *failingStore) Take(ctx context.Context, key string) ([]byte, bool, error) {
	if s.fail["take"] {
		return nil, false, s.refusal("take", key)
	}
	return s.Store.Take(ctx, key)
}

func (s *failingStore) SetMany(ctx context.Context, entries ...kv.Entry) error {
	if s.fail["set"] {
		return s.refusal("set", entries[0].Key)
	}
	return s.Store.SetMany(ctx, entries...)
}

// assertGenericError holds a response to a server error that says nothing of the cause.
func assertGenericError(t *testing.T, rec *httptest.ResponseRecorder, secrets ...string) {
	t.Helper()
	body := rec.Body.String() + rec.Header().Get("Location")
	if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusFound {
		t.Errorf("status = %d: %s", rec.Code, body)
	}
	for _, value := range append([]string{testInternals, "as:", "kv/postgres"}, secrets...) {
		if value != "" && strings.Contains(body, value) {
			t.Errorf("the client reads %q in %s", value, body)
		}
	}
}

// Server rule 2: uniform errors that leak no internals. The store's text can carry its key, as:code:<the code> among them.
func TestServerRule2_AStoreFailureReachesTheClientAsAGenericErrorAndTheLogWithoutTheSecret(t *testing.T) {
	for name, run := range map[string]func(t *testing.T, server *Server, store *failingStore, assertion string, op *fakeOP) (*httptest.ResponseRecorder, string){
		"token endpoint looking up the code": func(t *testing.T, server *Server, store *failingStore, assertion string, _ *fakeOP) (*httptest.ResponseRecorder, string) {
			store.fail["take"] = true
			rec := httptest.NewRecorder()
			server.handle(server.TokenEndpoint).ServeHTTP(rec, authorizationCodeRequest(t, assertion, "client-code-value"))
			return rec, "client-code-value"
		},
		"token endpoint saving the session": func(t *testing.T, server *Server, store *failingStore, assertion string, op *fakeOP) (*httptest.ResponseRecorder, string) {
			done := callback(server, url.Values{"state": {op.login.State}, "code": {"op-code-value"}})
			location, err := url.Parse(done.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			code := location.Query().Get("code")
			store.fail["set"] = true
			rec := httptest.NewRecorder()
			server.handle(server.TokenEndpoint).ServeHTTP(rec, authorizationCodeRequest(t, assertion, code))
			return rec, code
		},
		"callback looking up the state": func(_ *testing.T, server *Server, store *failingStore, _ string, op *fakeOP) (*httptest.ResponseRecorder, string) {
			store.fail["take"] = true
			return callback(server, url.Values{"state": {op.login.State}, "code": {"op-code-value"}}), op.login.State
		},
		"callback saving the session": func(_ *testing.T, server *Server, store *failingStore, _ string, op *fakeOP) (*httptest.ResponseRecorder, string) {
			store.fail["set"] = true
			return callback(server, url.Values{"state": {op.login.State}, "code": {"op-code-value"}}), op.login.State
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, signKey := newTestServer(t)
			store := &failingStore{Store: kv.NewMemory(), fail: map[string]bool{}}
			server.sessionStore = newKVSessionStore(store, time.Hour)
			op := &fakeOP{}
			pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
			assertion := signClientAssertion(t, server, signKey, nil)
			logs := captureDebugLogs(t)
			rec, secret := run(t, server, store, assertion, op)
			// Once the callback knows the client, the failure ends there (RFC 6749 section 4.1.2.1).
			want := http.StatusInternalServerError
			if name == "callback saving the session" {
				want = http.StatusFound
			}
			if rec.Code != want {
				t.Errorf("status = %d: %s", rec.Code, rec.Body)
			}
			assertGenericError(t, rec, secret)
			if !strings.Contains(logs.String(), testInternals) {
				t.Errorf("the detail is gone from the log:\n%s", logs)
			}
			assertNoneInLog(t, logs, secret)
		})
	}
}

// RFC 6749 section 5.2: a code that does not exist or was used is invalid_grant, and no server error.
func TestRFC6749_5_2_AnUnknownCodeIsInvalidGrant(t *testing.T) {
	server, signKey := newTestServer(t)
	rec := httptest.NewRecorder()
	server.handle(server.TokenEndpoint).ServeHTTP(rec, authorizationCodeRequest(t, signClientAssertion(t, server, signKey, nil), "unknown-code-value"))
	var body Error
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || body.Code != "invalid_grant" {
		t.Errorf("%d %+v", rec.Code, body)
	}
	if strings.Contains(rec.Body.String(), "unknown-code-value") {
		t.Errorf("echoed: %s", rec.Body)
	}
}

// Server rule 2: uniform error responses that leak no internals.
func TestServerRule2_AProviderFailureReachesTheClientAsAGenericError(t *testing.T) {
	t.Run("the authorization URL", func(t *testing.T) {
		server, signKey := newTestServer(t)
		op := &fakeOP{}
		pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
		op.authErr = errors.New(testInternals)
		session := &Session{ID: "s", RedirectURI: "https://rp.example.com/callback", State: "st-123", IDPIss: testOPIssuer}
		rec := httptest.NewRecorder()
		if err := server.startOpenidProviderLogin(rec, httptest.NewRequest(http.MethodGet, "/auth", nil), session, &Product{}); err != nil {
			t.Fatal(err)
		}
		assertGenericError(t, rec)
	})
	t.Run("an issuer that cannot be resolved", func(t *testing.T) {
		server, _ := newTestServer(t)
		session := &Session{ID: "s", RedirectURI: "https://rp.example.com/callback", State: "st-123", IDPIss: "https://" + testInternals}
		rec := httptest.NewRecorder()
		if err := server.startOpenidProviderLogin(rec, httptest.NewRequest(http.MethodGet, "/auth", nil), session, &Product{}); err != nil {
			t.Fatal(err)
		}
		assertGenericError(t, rec)
	})
	t.Run("the exchange", func(t *testing.T) {
		server, signKey := newTestServer(t)
		op := &fakeOP{}
		opState := pendingLogin(t, server, signClientAssertion(t, server, signKey, nil), op)
		op.exchangeErr = errors.New(testInternals)
		assertGenericError(t, callback(server, url.Values{"state": {opState}, "code": {"c"}}))
	})
	t.Run("the federation's list", func(t *testing.T) {
		server, _ := newTestServer(t)
		server.providers = providers.New(failingFederation{})
		rec := httptest.NewRecorder()
		server.handle(server.OpenidProvidersEndpoint).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openid-providers", nil))
		assertGenericError(t, rec)
	})
}

type failingFederation struct{}

func (failingFederation) Provider(context.Context, string) (providers.Provider, error) {
	return providers.Provider{}, errors.New(testInternals)
}

func (failingFederation) Providers(context.Context) ([]providers.Info, error) {
	return nil, errors.New(testInternals)
}

// Server rule 2: uniform error responses that leak no internals.
func TestServerRule2_AHandlerErrorOfNoOAuthKindIsGeneric(t *testing.T) {
	server, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	server.handle(func(http.ResponseWriter, *http.Request) error {
		return errors.New(testInternals)
	}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertGenericError(t, rec)
}

// Server rule 17: a private JWK in public_jwk would work through its public half, with the private half in a configuration file that is
// not kept as a secret.
func TestServerRule17_ARegisteredClientKeyThatIsNotPublicIsRefusedAtLoad(t *testing.T) {
	private := newP256(t)
	for name, key := range map[string]any{
		"an EC private key": private,
		"a symmetric key":   []byte("symmetric-key-of-thirty-two-byte"),
	} {
		t.Run(name, func(t *testing.T) {
			jwk := jwkToMap(t, &jose.JSONWebKey{Key: key})
			_, err := NewStaticClientsRegistry([]Client{{ClientID: "c", ProductID: "p", PublicJWK: jwk}})
			if err == nil {
				t.Fatal("accepted")
			}
			for _, member := range []string{"d", "k"} {
				if value, ok := jwk[member].(string); ok && strings.Contains(err.Error(), value) {
					t.Errorf("the error holds the key: %v", err)
				}
			}
		})
	}
	public := private.Public()
	if _, err := NewStaticClientsRegistry([]Client{{ClientID: "c", ProductID: "p", PublicJWK: jwkToMap(t, &jose.JSONWebKey{Key: public})}}); err != nil {
		t.Errorf("the public half: %v", err)
	}
}

// Server rule 14: identifiers in telemetry are pseudonymised.
func TestServerRule14_SessionRefCorrelatesAndRevealsNoPartOfTheID(t *testing.T) {
	const id = "0f8fad5b-d9cb-469f-a165-70867728950e"
	ref := sessionRef(id)
	if again := sessionRef(id); again != ref {
		t.Errorf("not stable: %q, %q", ref, again)
	}
	if len(ref) > 16 || strings.Contains(id, ref) {
		t.Errorf("ref %q", ref)
	}
}
