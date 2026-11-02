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

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth"
)

// opStub is an OpenID provider with one signing key, whose token endpoint answers with idToken.
type opStub struct {
	*httptest.Server
	key     *ecdsa.PrivateKey
	idToken string
}

func newOPStub(t *testing.T) *opStub {
	t.Helper()
	stub := &opStub{key: newECKey(t, elliptic.P256())}
	publicKey := jose.JSONWebKey{Key: stub.key.Public(), KeyID: "k"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DiscoveryDocument{
			Issuer:                stub.URL,
			AuthorizationEndpoint: stub.URL + "/authorize",
			TokenEndpoint:         stub.URL + "/token",
			JwksURI:               stub.URL + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": stub.idToken})
	})
	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)
	return stub
}

func (s *opStub) client(t *testing.T) Client {
	t.Helper()
	client, err := NewClient(Config{
		Issuer:       s.URL,
		ClientID:     "client",
		ClientSecret: NewSecretString("secret"),
		RedirectURI:  "https://rp.example/cb",
		Scopes:       []string{"openid"},
		HTTPClient:   s.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (s *opStub) claims() []byte {
	return fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":"n","exp":%d}`, s.URL, time.Now().Add(time.Hour).Unix())
}

func TestExchangeAcceptsTokenFromAKeyWithoutAlg(t *testing.T) {
	stub := newOPStub(t)
	client := stub.client(t)
	stub.idToken = signToken(t, jose.ES256, stub.key, "k", stub.claims())
	response, err := client.Exchange(t.Context(), Login{Verifier: "verifier"}, "code")
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := response.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims.Nonce != "n" {
		t.Errorf("nonce = %q", claims.Nonce)
	}
}

func TestExchangeRefuses(t *testing.T) {
	stub := newOPStub(t)
	client := stub.client(t)
	forged := newECKey(t, elliptic.P256())
	for name, token := range map[string]string{
		"a signature by another key": signToken(t, jose.ES256, forged, "k", stub.claims()),
		"a token without alg":        signRawES256(t, stub.key, map[string]string{"kid": "k"}, stub.claims()),
		"an unknown kid":             signToken(t, jose.ES256, stub.key, "unknown", stub.claims()),
		"another audience":           signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"other","nonce":"n","exp":%d}`, stub.URL, time.Now().Add(time.Hour).Unix())),
		"another issuer":             signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":"https://evil.example","aud":"client","nonce":"n","exp":%d}`, time.Now().Add(time.Hour).Unix())),
		"no nonce":                   signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","exp":%d}`, stub.URL, time.Now().Add(time.Hour).Unix())),
		"no exp":                     signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":"n"}`, stub.URL)),
		"expired past the skew":      signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":"n","exp":%d}`, stub.URL, time.Now().Add(-defaultAcceptableSkew-time.Second).Unix())),
	} {
		t.Run(name, func(t *testing.T) {
			stub.idToken = token
			if _, err := client.Exchange(t.Context(), Login{Verifier: "verifier"}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestExchangeToleratesExpiryWithinTheSkew(t *testing.T) {
	stub := newOPStub(t)
	client := stub.client(t)
	stub.idToken = signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":"n","exp":%d}`, stub.URL, time.Now().Add(-defaultAcceptableSkew/2).Unix()))
	if _, err := client.Exchange(t.Context(), Login{Verifier: "verifier"}, "code"); err != nil {
		t.Error(err)
	}
}

func TestNewClientFailsWhenTheKeySetCannotBeFetched(t *testing.T) {
	mux := http.NewServeMux()
	var server *httptest.Server
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: server.URL, JwksURI: server.URL + "/missing"})
	})
	server = httptest.NewServer(mux)
	defer server.Close()
	_, err := NewClient(Config{Issuer: server.URL, HTTPClient: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "failed to fetch signing keys") {
		t.Errorf("err = %v", err)
	}
}

func TestAuthenticationURLCarriesTheS256Challenge(t *testing.T) {
	stub := newOPStub(t)
	authURL, err := stub.client(t).AuthenticationURL(t.Context(), Login{State: "state", Nonce: "nonce", Verifier: "verifier"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "code_challenge="+oauth.S256Challenge("verifier")) || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("url = %s", authURL)
	}
}
