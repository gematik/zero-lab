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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

const (
	testIssuer    = "https://as.example.com"
	testClientID  = "test-client"
	testProductID = "test-product"
	testScope     = "test-scope"
)

// testDPoPKey is the client's DPoP key: client assertions name it as cnf.jkt, and token requests carry a
// proof it signed.
var testDPoPKey = func() *dpop.Key {
	k, err := dpop.NewKey()
	if err != nil {
		panic(err)
	}
	return k
}()

// newTestServer builds an authorization server with one product and one client whose public JWK is
// derived from the returned signing key. The signing key is used to mint client assertions.
func newTestServer(t *testing.T) (*Server, *jose.JSONWebKey) {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signKey := &jose.JSONWebKey{Key: prk, KeyID: "test-client-key"}
	pubKey := signKey.Public()

	cfg := Config{
		Issuer:     testIssuer,
		SigningKey: &SigningKey{Signer: newP256(t), KeyID: "test-server-key"},
		Products: []Product{{
			ProductID:    testProductID,
			RedirectURIs: []string{"https://rp.example.com/callback"},
			Scopes:       []string{testScope},
		}},
		Clients: []Client{{
			ClientID:  testClientID,
			ProductID: testProductID,
			PublicJWK: jwkToMap(t, &pubKey),
		}},
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server, signKey
}

func jwkToMap(t *testing.T, key *jose.JSONWebKey) map[string]any {
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
func signClientAssertion(t *testing.T, server *Server, signKey *jose.JSONWebKey, mutate func(map[string]any)) string {
	t.Helper()
	nonce, err := server.nonceService.Get()
	if err != nil {
		t.Fatalf("get nonce: %v", err)
	}
	claims := map[string]any{
		"iss":   testClientID,
		"sub":   testClientID,
		"aud":   []string{testIssuer},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Minute).Unix(),
		"nonce": nonce,
		"cnf":   map[string]string{"jkt": testDPoPKey.Thumbprint()},
	}
	if mutate != nil {
		mutate(claims)
	}
	return signES256(t, signKey, claims)
}

func signES256(t *testing.T, key *jose.JSONWebKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode claims: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return signed
}

// clientCredentialsRequest is a client_credentials token request with a DPoP proof by testDPoPKey.
func clientCredentialsRequest(t *testing.T, assertion string) *http.Request {
	t.Helper()
	return clientCredentialsRequestWithProof(t, assertion, testDPoPKey)
}

// clientCredentialsRequestWithProof is a client_credentials token request with a DPoP proof by proofKey,
// or none when proofKey is nil.
func clientCredentialsRequestWithProof(t *testing.T, assertion string, proofKey *dpop.Key) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", GrantTypeClientCredentials)
	form.Set("scope", testScope)
	form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	req := httptest.NewRequest(http.MethodPost, testIssuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proofKey != nil {
		if err := proofKey.Sign(req, dpop.ProofOptions{}); err != nil {
			t.Fatalf("sign DPoP proof: %v", err)
		}
	}
	return req
}

// TestPrivateKeyJWTClientCredentials drives a full client_credentials exchange authenticated with a
// private_key_jwt assertion and asserts the issued access token is DPoP-bound to the assertion's
// cnf.jkt.
func TestPrivateKeyJWTClientCredentials(t *testing.T) {
	server, signKey := newTestServer(t)
	assertion := signClientAssertion(t, server, signKey, nil)

	resp := httptest.NewRecorder()
	if err := server.TokenEndpoint(resp, clientCredentialsRequest(t, assertion)); err != nil {
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

	parts := strings.Split(tr.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a compact JWS: %q", tr.AccessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token: %v", err)
	}
	var claims struct {
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("access token claims: %v", err)
	}
	if claims.Cnf.Jkt != testDPoPKey.Thumbprint() {
		t.Fatalf("cnf.jkt = %v, want %q", claims.Cnf.Jkt, testDPoPKey.Thumbprint())
	}
}

// RFC 9449 Section 5: a client "MUST provide a valid DPoP proof JWT in a DPoP header" for "all access token
// requests regardless of grant type". A client_credentials request whose assertion names a key, without a
// proof by it, gets no token bound to that key.
func TestRFC9449_5_ClientCredentialsWithoutProofIsRefused(t *testing.T) {
	server, signKey := newTestServer(t)
	req := clientCredentialsRequestWithProof(t, signClientAssertion(t, server, signKey, nil), nil)
	assertTokenError(t, server.TokenEndpoint(httptest.NewRecorder(), req), "invalid_dpop_proof", "no DPoP proof")
}

// RFC 9449 Section 5: the token is bound to the key of the proof; a proof by a key other than the one the
// assertion names does not bind the token to the named key.
func TestRFC9449_5_ClientCredentialsProofByAnotherKeyIsRefused(t *testing.T) {
	server, signKey := newTestServer(t)
	other, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	req := clientCredentialsRequestWithProof(t, signClientAssertion(t, server, signKey, nil), other)
	assertTokenError(t, server.TokenEndpoint(httptest.NewRecorder(), req),
		"invalid_dpop_proof", "DPoP proof key is not the key the grant is bound to")
}

// RFC 9449 Section 4.3: the proof is checked for this token endpoint; one made for another URI is refused.
func TestRFC9449_5_ClientCredentialsProofForAnotherEndpointIsRefused(t *testing.T) {
	server, signKey := newTestServer(t)
	req := clientCredentialsRequestWithProof(t, signClientAssertion(t, server, signKey, nil), nil)
	proof, err := testDPoPKey.Proof(http.MethodPost, testIssuer+"/par", dpop.ProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(dpop.HeaderName, proof)
	assertTokenError(t, server.TokenEndpoint(httptest.NewRecorder(), req),
		"invalid_dpop_proof", "DPoP proof htu does not match the request URI")
}

func assertTokenError(t *testing.T, err error, code, description string) {
	t.Helper()
	var authzErr *Error
	if !errors.As(err, &authzErr) || authzErr.HTTPStatus != http.StatusBadRequest ||
		authzErr.Code != code || authzErr.Description != description {
		t.Fatalf("got %v, want 400 %s: %s", err, code, description)
	}
}

// TestServerRule11_PrivateKeyJWTNonceIsSingleUse verifies a redeemed nonce cannot be replayed.
func TestServerRule11_PrivateKeyJWTNonceIsSingleUse(t *testing.T) {
	server, signKey := newTestServer(t)
	assertion := signClientAssertion(t, server, signKey, nil)

	if err := server.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion)); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	err := server.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion))
	assertInvalidClient(t, err)
}

// RFC 7523 Section 3: signature, iss, sub, aud and exp of the assertion are checked; nonce and cnf are this server's own.
func TestRFC7523_3_PrivateKeyJWTRejections(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongKey := &jose.JSONWebKey{Key: otherKey}

	cases := []struct {
		name   string
		mutate func(map[string]any)
		// when set, the assertion is signed with this key instead of the registered one
		signWith *jose.JSONWebKey
		// when set, replace the client_assertion_type with this value
		assertionType string
	}{
		{name: "wrong signing key", signWith: wrongKey},
		{name: "unknown client", mutate: func(c map[string]any) { c["sub"] = "nobody" }},
		{name: "iss != sub", mutate: func(c map[string]any) { c["iss"] = "someone-else" }},
		{name: "wrong audience", mutate: func(c map[string]any) { c["aud"] = []string{"https://evil.example.com"} }},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{name: "missing nonce", mutate: func(c map[string]any) { delete(c, "nonce") }},
		{name: "missing cnf", mutate: func(c map[string]any) { delete(c, "cnf") }},
		{name: "unknown nonce", mutate: func(c map[string]any) { c["nonce"] = "never-issued" }},
		{name: "wrong assertion type", assertionType: "urn:bogus"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, signKey := newTestServer(t)
			if tc.signWith != nil {
				signKey = tc.signWith
			}
			assertion := signClientAssertion(t, server, signKey, tc.mutate)
			req := clientCredentialsRequest(t, assertion)
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
	authzErr := &Error{}
	ok := errors.As(err, &authzErr)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if authzErr.Code != "invalid_client" {
		t.Fatalf("error code = %q, want invalid_client (%s)", authzErr.Code, authzErr.Description)
	}
}
