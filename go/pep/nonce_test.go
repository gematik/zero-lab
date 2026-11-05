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

// Package pep is a policy enforcement point for HTTP resources: Enforcers decide on each request from its
// access token, DPoP proof or session cookie, and a denial becomes an OAuth 2.0 error response.
package pep_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

// nonceServer is a resource behind an authorization_dpop enforcer that requires a nonce, at a PEP
// whose nonces come from source; a nil source configures none.
func nonceServer(t *testing.T, source dpop.NonceSource) *httptest.Server {
	t.Helper()
	jwkSet, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	builder := pep.NewBuilder().Resource("https://example.com").PublicOrigin(server.URL).WithJWKSet(jwkSet)
	if source != nil {
		builder = builder.WithDPoPNonces(source)
	}
	p, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/dpop", p.GuardedHandlerFunc(&pep.EnforcerAuthorizationDPoP{NonceRequired: true},
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	return server
}

// nonces is a NonceSource that remembers what it handed out. pep depends on dpop alone, so the tests
// stand in for go/nonce, whose own tests prove that its sealed nonces hold across replicas sharing keys.
type nonces struct {
	mu     sync.Mutex
	issued map[string]bool
}

func newNonces() *nonces { return &nonces{issued: map[string]bool{}} }

func (n *nonces) Valid(nonce string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.issued[nonce]
}

func (n *nonces) Fresh() (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	nonce := rand.Text()
	n.issued[nonce] = true
	return nonce, nil
}

// call sends a DPoP request with a fresh proof key, carrying proofNonce.
func call(t *testing.T, server *httptest.Server, proofNonce string) *http.Response {
	t.Helper()
	proofKey, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := createTestAccessToken([]byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour), proofKey.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/dpop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := proofKey.Sign(req, dpop.ProofOptions{AccessToken: accessToken, Nonce: proofNonce}); err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func assertNonceHandedOut(t *testing.T, resp *http.Response) string {
	t.Helper()
	got := resp.Header.Get("DPoP-Nonce")
	if got == "" {
		t.Fatal("no DPoP-Nonce")
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "DPoP-Nonce") {
		t.Errorf("Access-Control-Expose-Headers = %q", resp.Header.Get("Access-Control-Expose-Headers"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	return got
}

// Without a nonce source, a requirement of nonces refuses every request rather than letting proofs pass
// unchecked.
func TestRFC9449_9_NoncesRequiredWithoutASourceAreRefused(t *testing.T) {
	resp := call(t, nonceServer(t, nil), "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// RFC 9449 Section 9: a proof without the server's nonce is answered with use_dpop_nonce and a nonce.
func TestRFC9449_9_AProofWithoutTheNonceIsAnsweredWithOne(t *testing.T) {
	server := nonceServer(t, newNonces())
	for name, proofNonce := range map[string]string{"none": "", "forged": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		t.Run(name, func(t *testing.T) {
			resp := call(t, server, proofNonce)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if challenge := resp.Header.Get("WWW-Authenticate"); !strings.Contains(challenge, `error="use_dpop_nonce"`) {
				t.Errorf("WWW-Authenticate = %q", challenge)
			}
			assertNonceHandedOut(t, resp)
		})
	}
}

// RFC 9449 Sections 8.2 and 9: a proof with the nonce is accepted, and the response carries the next one.
func TestRFC9449_9_AProofWithTheNonceIsAcceptedAndGetsTheNext(t *testing.T) {
	server := nonceServer(t, newNonces())
	first := assertNonceHandedOut(t, call(t, server, ""))
	resp := call(t, server, first)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	assertNonceHandedOut(t, resp)
}

// RFC 9449 Section 9: replicas whose nonce source accepts the same nonces accept each other's, so the PEP
// keeps none of its own.
func TestRFC9449_9_ANonceOfOneReplicaIsAcceptedByAnother(t *testing.T) {
	shared := newNonces()
	one := nonceServer(t, shared)
	other := nonceServer(t, shared)
	handedOut := assertNonceHandedOut(t, call(t, one, ""))
	if resp := call(t, other, handedOut); resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	stranger := nonceServer(t, newNonces())
	if resp := call(t, stranger, handedOut); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a replica with other keys: status = %d", resp.StatusCode)
	}
}
