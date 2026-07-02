package authzserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testIssuer    = "https://as.example.com"
	testClientID  = "test-client"
	testProductID = "test-product"
	testScope     = "test-scope"
	testJkt       = "test-dpop-thumbprint"
)

// newTestServer builds an authorization server with one product and one client whose public JWK is
// derived from the returned signing key. The signing key is used to mint client assertions.
func newTestServer(t *testing.T) (*Server, jwk.Key) {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signKey, err := jwk.Import(prk)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}
	signKey.Set(jwk.KeyIDKey, "test-client-key")
	pubKey, err := signKey.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	cfg := Config{
		Issuer: testIssuer,
		Products: []Product{{
			ProductID:    testProductID,
			RedirectURIs: []string{"https://rp.example.com/callback"},
			Scopes:       []string{testScope},
		}},
		Clients: []Client{{
			ClientID:  testClientID,
			ProductID: testProductID,
			PublicJWK: jwkToMap(t, pubKey),
		}},
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server, signKey
}

func jwkToMap(t *testing.T, key jwk.Key) map[string]any {
	t.Helper()
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	return m
}

// signClientAssertion mints a private_key_jwt assertion with a fresh nonce, applying mutate (if any)
// before signing so tests can tamper with individual claims.
func signClientAssertion(t *testing.T, server *Server, signKey jwk.Key, mutate func(jwt.Token)) string {
	t.Helper()
	nonce, err := server.nonceService.Get()
	if err != nil {
		t.Fatalf("get nonce: %v", err)
	}
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, testClientID)
	tok.Set(jwt.SubjectKey, testClientID)
	tok.Set(jwt.AudienceKey, testIssuer)
	tok.Set(jwt.IssuedAtKey, time.Now().Unix())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Minute).Unix())
	tok.Set("nonce", nonce)
	tok.Set("cnf", map[string]string{"jkt": testJkt})
	if mutate != nil {
		mutate(tok)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signKey))
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return string(signed)
}

func clientCredentialsRequest(assertion, scope string) *http.Request {
	form := url.Values{}
	form.Set("grant_type", GrantTypeClientCredentials)
	form.Set("scope", scope)
	form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	req := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestPrivateKeyJWTClientCredentials drives a full client_credentials exchange authenticated with a
// private_key_jwt assertion and asserts the issued access token is DPoP-bound to the assertion's
// cnf.jkt.
func TestPrivateKeyJWTClientCredentials(t *testing.T) {
	server, signKey := newTestServer(t)
	assertion := signClientAssertion(t, server, signKey, nil)

	resp := httptest.NewRecorder()
	if err := server.TokenEndpoint(resp, clientCredentialsRequest(assertion, testScope)); err != nil {
		t.Fatalf("token endpoint returned error: %v", err)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.Code, resp.Body.String())
	}

	var tr TokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("no access token issued")
	}
	if tr.TokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP (cnf.jkt bound)", tr.TokenType)
	}

	tok, err := jwt.Parse([]byte(tr.AccessToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	var cnf map[string]any
	if err := tok.Get("cnf", &cnf); err != nil {
		t.Fatalf("access token missing cnf: %v", err)
	}
	if cnf["jkt"] != testJkt {
		t.Fatalf("cnf.jkt = %v, want %q", cnf["jkt"], testJkt)
	}
}

// TestPrivateKeyJWTNonceIsSingleUse verifies a redeemed nonce cannot be replayed.
func TestPrivateKeyJWTNonceIsSingleUse(t *testing.T) {
	server, signKey := newTestServer(t)
	assertion := signClientAssertion(t, server, signKey, nil)

	if err := server.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(assertion, testScope)); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	err := server.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(assertion, testScope))
	assertInvalidClient(t, err)
}

func TestPrivateKeyJWTRejections(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongKey, err := jwk.Import(otherKey)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(jwt.Token)
		// when set, the assertion is signed with this key instead of the registered one
		signWith jwk.Key
		// when set, replace the client_assertion_type with this value
		assertionType string
	}{
		{name: "wrong signing key", signWith: wrongKey},
		{name: "unknown client", mutate: func(tok jwt.Token) { tok.Set(jwt.SubjectKey, "nobody") }},
		{name: "iss != sub", mutate: func(tok jwt.Token) { tok.Set(jwt.IssuerKey, "someone-else") }},
		{name: "wrong audience", mutate: func(tok jwt.Token) { tok.Set(jwt.AudienceKey, "https://evil.example.com") }},
		{name: "expired", mutate: func(tok jwt.Token) { tok.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour).Unix()) }},
		{name: "missing nonce", mutate: func(tok jwt.Token) { tok.Remove("nonce") }},
		{name: "missing cnf", mutate: func(tok jwt.Token) { tok.Remove("cnf") }},
		{name: "unknown nonce", mutate: func(tok jwt.Token) { tok.Set("nonce", "never-issued") }},
		{name: "wrong assertion type", assertionType: "urn:bogus"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, signKey := newTestServer(t)
			if tc.signWith != nil {
				signKey = tc.signWith
			}
			assertion := signClientAssertion(t, server, signKey, tc.mutate)
			req := clientCredentialsRequest(assertion, testScope)
			if tc.assertionType != "" {
				form := url.Values{}
				form.Set("grant_type", GrantTypeClientCredentials)
				form.Set("scope", testScope)
				form.Set("client_assertion_type", tc.assertionType)
				form.Set("client_assertion", assertion)
				req = httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			assertInvalidClient(t, server.TokenEndpoint(httptest.NewRecorder(), req))
		})
	}
}

func assertInvalidClient(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected client authentication to fail, got nil")
	}
	authzErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if authzErr.Code != "invalid_client" {
		t.Fatalf("error code = %q, want invalid_client (%s)", authzErr.Code, authzErr.Description)
	}
}
