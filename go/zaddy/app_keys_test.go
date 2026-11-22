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

package zaddy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/pep"
)

// fakeAuthorizationServer serves RFC 8414 metadata naming issuer, its URL unless a test changes it, and a key set.
type fakeAuthorizationServer struct {
	*httptest.Server
	issuer      atomic.Value
	jwksFetches atomic.Int32
}

func newFakeAuthorizationServer(t *testing.T, key *ecdsa.PrivateKey) *fakeAuthorizationServer {
	t.Helper()
	as := &fakeAuthorizationServer{}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k0", Algorithm: string(jose.ES256), Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	as.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pep.AuthorizationServerMetadataPath:
			issuer, _ := as.issuer.Load().(string)
			if issuer == "" {
				issuer = as.URL
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, as.URL+"/jwks")
		case "/jwks":
			as.jwksFetches.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(as.Close)
	return as
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func accessToken(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(fmt.Appendf(nil, `{"aud":"https://rs.example","exp":%d}`, time.Now().Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func startableApp(t *testing.T, as *fakeAuthorizationServer) *App {
	t.Helper()
	a := &App{Resource: "https://rs.example", AuthorizationServer: as.URL, logger: slog.New(slog.DiscardHandler), egressClient: as.Client()}
	if err := a.loadNonceKeys(); err != nil {
		t.Fatal(err)
	}
	return a
}

// servers.md rule 17: without jwks_path zaddy reads the authorization server's keys when it starts, and does not
// start when they cannot be had; with them, its PEP verifies the server's tokens.
func TestServerRule17_ZaddyStartsOnlyWithTheAuthorizationServersKeys(t *testing.T) {
	key := generateKey(t)
	as := newFakeAuthorizationServer(t, key)
	a := startableApp(t, as)
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Stop() })
	if _, err := a.pep.VerifyAccessToken(accessToken(t, key, "k0")); err != nil {
		t.Errorf("a token of the authorization server was refused: %v", err)
	}

	mismatched := newFakeAuthorizationServer(t, key)
	mismatched.issuer.Store("https://as.example")
	b := startableApp(t, mismatched)
	if err := b.Start(); err == nil || b.pep != nil {
		t.Errorf("started with keys of another issuer: %v", err)
	}
}

// Without jwks_path the keys come from authorization_server, so one of the two is required; authorization_server
// is an issuer identifier, https without query or fragment (RFC 8414 Section 2).
func TestRFC8414_2_ZaddyRequiresJWKSPathOrAnHTTPSAuthorizationServer(t *testing.T) {
	for block, ok := range map[string]bool{
		"pep {\n resource https://api.example.com\n}":                                                      false,
		"pep {\n resource https://api.example.com\n jwks_path jwks.json\n}":                                true,
		"pep {\n resource https://api.example.com\n authorization_server https://as.example.com\n}":        true,
		"pep {\n resource https://api.example.com\n authorization_server http://as.example.com\n}":         false,
		"pep {\n resource https://api.example.com\n authorization_server https://as.example.com?a=b\n}":    false,
		"pep {\n resource https://api.example.com\n jwks_path j.json\n authorization_server as.example\n}": false,
	} {
		a, err := parsePEPBlock(t, block)
		if err == nil {
			err = a.Validate()
		}
		if (err == nil) != ok {
			t.Errorf("%q: %v", block, err)
		}
	}
}

// servers.md rule 8: the app fetches the set in the background, outside the request path, and Stop ends the loop.
func TestServerRule8_TheKeysAreRefreshedInTheBackgroundUntilStop(t *testing.T) {
	as := newFakeAuthorizationServer(t, generateKey(t))
	keys, err := pep.NewAuthorizationServerKeys(pep.AuthorizationServerKeysConfig{Issuer: as.URL, HTTPClient: as.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		refreshKeys(ctx, keys, time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for as.jwksFetches.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if as.jwksFetches.Load() < 3 {
		t.Fatal("the set was not fetched in the background")
	}
	if _, err := keys.Keys(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the background refresh did not stop")
	}
}
