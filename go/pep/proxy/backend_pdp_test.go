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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

func testSigningKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &jose.JSONWebKey{Key: prk, KeyID: "test-pep-client"}
}

func TestPDPClientAssertionClaims(t *testing.T) {
	b := &pdpBackend{
		cfg:  PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t)},
		meta: asMetadata{Issuer: "https://as.example"}, // no NonceEndpoint → skip nonce fetch
	}
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{ID: "s1", DPoPKeyJWK: jwkJSON}

	assertion, err := b.clientAssertion(context.Background(), sess)
	if err != nil {
		t.Fatalf("clientAssertion: %v", err)
	}
	parsed, err := jose.ParseSignedCompact(assertion, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	payload, err := parsed.Verify(b.cfg.SigningKey.Public().Key)
	if err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	var claims struct {
		Iss string   `json:"iss"`
		Aud []string `json:"aud"`
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode assertion: %v", err)
	}
	if claims.Iss != "pep-client" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "https://as.example" {
		t.Errorf("aud = %v", claims.Aud)
	}
	if claims.Cnf.Jkt == "" {
		t.Error("cnf.jkt missing")
	}
}

func TestPDPStartLoginPreparesSession(t *testing.T) {
	b := &pdpBackend{
		cfg:  PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t), RedirectURI: "https://pep/oauth2/callback"},
		meta: asMetadata{Issuer: "https://as.example", AuthorizationEndpoint: "https://as.example/auth"}, http: http.DefaultClient, signer: sessionKeySigner{},
	}
	sess := &Session{ID: "s1"}
	ls, err := b.StartLogin(context.Background(), sess, "", "test-scope")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if sess.DPoPKeyJWK == nil || sess.State == "" || sess.CodeVerifier == "" {
		t.Fatalf("session not prepared: %+v", sess)
	}
	if !strings.HasPrefix(ls.AuthURL, "https://as.example/auth") {
		t.Errorf("AuthURL = %q", ls.AuthURL)
	}
}

func TestPDPTokenRequestSendsDPoP(t *testing.T) {
	var gotDPoP string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get(dpop.HeaderName)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":300,"token_type":"DPoP"}`))
	}))
	defer ts.Close()
	b := &pdpBackend{
		cfg:  PDPConfig{ASIssuer: "https://as.example", ClientID: "c", SigningKey: testSigningKey(t)},
		meta: asMetadata{Issuer: "https://as.example", TokenEndpoint: ts.URL}, http: ts.Client(), signer: sessionKeySigner{},
	}
	_, jwkJSON, _ := newSessionDPoPKey()
	sess := &Session{ID: "s1", DPoPKeyJWK: jwkJSON}
	tr, err := b.tokenRequest(context.Background(), sess, url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}})
	if err != nil {
		t.Fatalf("tokenRequest: %v", err)
	}
	if tr.AccessToken != "at" {
		t.Errorf("access_token = %q", tr.AccessToken)
	}
	if gotDPoP == "" {
		t.Fatal("no DPoP header sent to /token — binding requires it")
	}
	proof := verifyDPoP(t, gotDPoP, dpop.Request{Method: http.MethodPost, URI: ts.URL})
	if proof.AccessTokenHash != "" {
		t.Errorf("token-request proof must carry no ath, got %q", proof.AccessTokenHash)
	}
}
