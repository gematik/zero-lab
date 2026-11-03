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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
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

// asStub serves authorization server metadata; doc gets the server's URL.
func asStub(t *testing.T, tls bool, doc func(base string) asMetadata) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(doc(server.URL))
		case "/elsewhere":
			_ = json.NewEncoder(w).Encode(doc(server.URL))
		default:
			http.NotFound(w, r)
		}
	})
	if tls {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server
}

func fullMetadata(base string) asMetadata {
	return asMetadata{
		Issuer:                             base,
		AuthorizationEndpoint:              base + "/auth",
		TokenEndpoint:                      base + "/token",
		IntrospectionEndpoint:              base + "/introspect",
		OpenidProvidersEndpoint:            base + "/providers",
		NonceEndpoint:                      base + "/nonce",
		PushedAuthorizationRequestEndpoint: base + "/par",
	}
}

func discover(t *testing.T, server *httptest.Server, issuer string) (Backend, error) {
	t.Helper()
	return NewPDPBackend(PDPConfig{ASIssuer: issuer, ClientID: "pep-client", SigningKey: testSigningKey(t), HTTPClient: server.Client()})
}

// RFC 8414 section 3.3: the issuer in the document must be identical to the one configured.
func TestRFC8414_3_3_MetadataNamingAnotherIssuerIsRefused(t *testing.T) {
	for name, named := range map[string]func(base string) string{
		"another issuer":     func(string) string { return "https://evil.example" },
		"no issuer":          func(string) string { return "" },
		"a trailing slash":   func(base string) string { return base + "/" },
		"another path below": func(base string) string { return base + "/tenant" },
	} {
		t.Run(name, func(t *testing.T) {
			server := asStub(t, true, func(base string) asMetadata {
				md := fullMetadata(base)
				md.Issuer = named(base)
				return md
			})
			if _, err := discover(t, server, server.URL); err == nil || !strings.Contains(err.Error(), "issuer") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRFC8414_MetadataOfAnHTTPSIssuerNeedsHTTPSEndpoints(t *testing.T) {
	endpoints := map[string]func(*asMetadata, string){
		"authorization_endpoint": func(md *asMetadata, plain string) { md.AuthorizationEndpoint = plain },
		"token_endpoint":         func(md *asMetadata, plain string) { md.TokenEndpoint = plain },
		"introspection_endpoint": func(md *asMetadata, plain string) { md.IntrospectionEndpoint = plain },
		"openid_providers":       func(md *asMetadata, plain string) { md.OpenidProvidersEndpoint = plain },
		"nonce_endpoint":         func(md *asMetadata, plain string) { md.NonceEndpoint = plain },
		"pushed_authorization":   func(md *asMetadata, plain string) { md.PushedAuthorizationRequestEndpoint = plain },
	}
	for name, set := range endpoints {
		t.Run(name, func(t *testing.T) {
			server := asStub(t, true, func(base string) asMetadata {
				md := fullMetadata(base)
				set(&md, "http://as.example/plain")
				return md
			})
			if _, err := discover(t, server, server.URL); err == nil || !strings.Contains(err.Error(), "https") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRFC8414_MetadataOfAnHTTPSIssuerWithHTTPSEndpointsIsTaken(t *testing.T) {
	server := asStub(t, true, fullMetadata)
	if _, err := discover(t, server, server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestRFC8414_AnIssuerOverPlainHTTPElsewhereThanThisMachineIsRefusedBeforeAnyFetch(t *testing.T) {
	var fetches atomic.Int64
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		fetches.Add(1)
		return nil, http.ErrHandlerTimeout
	})}
	_, err := NewPDPBackend(PDPConfig{ASIssuer: "http://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t), HTTPClient: client})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v", err)
	}
	if n := fetches.Load(); n != 0 {
		t.Errorf("%d fetches", n)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRFC8414_AnIssuerOverPlainHTTPOnThisMachineMayHavePlainEndpoints(t *testing.T) {
	server := asStub(t, false, fullMetadata)
	if _, err := discover(t, server, server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverMetadataDoesNotFollowARedirect(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	var followed atomic.Int64
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		_ = json.NewEncoder(w).Encode(fullMetadata(server.URL))
	})
	if _, err := discover(t, server, server.URL); err == nil {
		t.Error("accepted")
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("%d requests followed the redirect", n)
	}
}

func TestDiscoverMetadataReadsNoMoreThanItsBound(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"padding":"`, server.URL, server.URL+"/auth", server.URL+"/token")
		for range maxASResponseBytes / 1024 {
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 1024))
		}
		fmt.Fprint(w, `"}`)
	}))
	defer server.Close()
	if _, err := discover(t, server, server.URL); err == nil {
		t.Error("read past the bound")
	}
}

// Every other endpoint answers within the same bound, or a member of the configuration could exhaust the proxy.
func TestPDPResponsesAreReadWithinTheirBound(t *testing.T) {
	huge := strings.Repeat(" ", maxASResponseBytes) + `{"request_uri":"urn:x","access_token":"at","active":true}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/par" {
			w.WriteHeader(http.StatusCreated)
		}
		fmt.Fprint(w, huge)
	}))
	defer server.Close()
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{ID: "s1", DPoPKeyJWK: jwkJSON}
	b := &pdpBackend{
		cfg: PDPConfig{ASIssuer: "https://as.example", ClientID: "c", SigningKey: testSigningKey(t)},
		meta: asMetadata{
			Issuer: "https://as.example", TokenEndpoint: server.URL + "/token", IntrospectionEndpoint: server.URL + "/introspect",
			OpenidProvidersEndpoint: server.URL + "/providers", PushedAuthorizationRequestEndpoint: server.URL + "/par",
		},
		http: server.Client(), signer: sessionKeySigner{},
	}
	if _, err := b.pushAuthorizationRequest(t.Context(), sess, url.Values{}); err == nil {
		t.Error("PAR read past the bound")
	}
	if _, err := b.tokenRequest(t.Context(), sess, url.Values{}); err == nil {
		t.Error("token read past the bound")
	}
	if _, err := b.introspectIdentity(t.Context(), sess, "at"); err == nil {
		t.Error("introspection read past the bound")
	}
	if _, err := b.fetchProviders(); err == nil {
		t.Error("providers read past the bound")
	}
}
