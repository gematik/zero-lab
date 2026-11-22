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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

// fakeAuthorizationServer serves its metadata and key set over TLS; the tests change both while it runs.
type fakeAuthorizationServer struct {
	*httptest.Server
	mu           sync.Mutex
	metadata     func(issuer string) string
	metadataPath string
	keys         *jose.JSONWebKeySet
	jwksStatus   int
	jwksFetches  atomic.Int32
}

func newFakeAuthorizationServer(t *testing.T, keys ...*ecdsa.PrivateKey) *fakeAuthorizationServer {
	t.Helper()
	as := &fakeAuthorizationServer{metadataPath: authorizationServerMetadataPath, jwksStatus: http.StatusOK}
	as.metadata = func(issuer string) string {
		return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q,"token_endpoint":%q}`, issuer, issuer+"/jwks", issuer+"/token")
	}
	as.setKeys(keys...)
	as.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		defer as.mu.Unlock()
		switch r.URL.Path {
		case as.metadataPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(as.metadata(as.URL)))
		case "/jwks":
			as.jwksFetches.Add(1)
			if as.jwksStatus != http.StatusOK {
				w.WriteHeader(as.jwksStatus)
				return
			}
			body, err := json.Marshal(as.keys)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/jwk-set+json")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(as.Close)
	return as
}

func (as *fakeAuthorizationServer) setKeys(keys ...*ecdsa.PrivateKey) {
	set := &jose.JSONWebKeySet{}
	for i, key := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: key.Public(), KeyID: fmt.Sprintf("k%d", i), Algorithm: string(jose.ES256), Use: "sig"})
	}
	as.mu.Lock()
	as.keys = set
	as.mu.Unlock()
}

func (as *fakeAuthorizationServer) set(change func()) {
	as.mu.Lock()
	defer as.mu.Unlock()
	change()
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

// RFC 8414 Section 3.3: the metadata must name exactly the issuer configured, or its keys are not the issuer's;
// RFC 8414 Section 2 and servers.md rule 30: a jwks_uri that is not https is refused, the keys must not travel
// without TLS. Either refuses the keys.
func TestRFC8414_3_3_AnIssuerMismatchOrANonHTTPSJwksURIRefusesTheKeys(t *testing.T) {
	for name, metadata := range map[string]func(string) string{
		"other issuer": func(issuer string) string {
			return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer+"/other", issuer+"/jwks")
		},
		"trailing slash": func(issuer string) string {
			return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer+"/", issuer+"/jwks")
		},
		"http jwks_uri": func(issuer string) string {
			return fmt.Sprintf(`{"issuer":%q,"jwks_uri":"http://as.example/jwks"}`, issuer)
		},
		"no jwks_uri": func(issuer string) string { return fmt.Sprintf(`{"issuer":%q}`, issuer) },
		"issuer twice": func(issuer string) string {
			return fmt.Sprintf(`{"issuer":%q,"issuer":%q,"jwks_uri":%q}`, issuer, issuer, issuer+"/jwks")
		},
		"not an object": func(string) string { return `["issuer"]` },
		"jwks_uri userinfo": func(issuer string) string {
			return fmt.Sprintf(`{"issuer":%q,"jwks_uri":"https://u:p@as.example/jwks"}`, issuer)
		},
	} {
		t.Run(name, func(t *testing.T) {
			as := newFakeAuthorizationServer(t, generateKey(t))
			as.metadata = metadata
			if _, err := newAuthorizationServerKeys(t.Context(), as.URL, as.Client(), time.Now); err == nil {
				t.Error("keys accepted")
			}
			if as.jwksFetches.Load() != 0 {
				t.Error("the key set was fetched from metadata that was refused")
			}
		})
	}
}

// RFC 8414 Section 3.1 with OpenID Connect Discovery 1.0 Section 4 as the fallback: an authorization server that
// answers 404 at RFC 8414's location is asked at /.well-known/openid-configuration, under the same issuer check.
func TestRFC8414_3_1_TheOpenIDConfigurationIsAskedWhenTheMetadataIsAbsent(t *testing.T) {
	as := newFakeAuthorizationServer(t, generateKey(t))
	as.metadataPath = openIDConfigurationPath
	keys, err := newAuthorizationServerKeys(t.Context(), as.URL, as.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if set, _ := keys.Keys(); len(set.Keys) != 1 {
		t.Errorf("keys %v", set)
	}
}

// RFC 8414 Section 3.1: the well-known segment goes between host and path, a terminating slash removed first.
func TestRFC8414_3_1_TheMetadataURLIsDerivedFromTheIssuer(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://as.example":          "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/":         "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/tenant/1": "https://as.example/.well-known/oauth-authorization-server/tenant/1",
	} {
		if got, err := authorizationServerMetadataURL(issuer); err != nil || got != want {
			t.Errorf("%s: %q, %v", issuer, got, err)
		}
	}
	for _, issuer := range []string{"http://as.example", "https://as.example?x=1", "https://as.example#f", "https://u@as.example", "as.example"} {
		if got, err := authorizationServerMetadataURL(issuer); err == nil {
			t.Errorf("%s: %q", issuer, got)
		}
	}
}

// servers.md rule 28, outbound responses: a key set holding a private key, an empty one, or one of another content
// type is refused.
func TestServerRule28_AKeySetThatIsNotPublicKeysIsRefused(t *testing.T) {
	private := generateKey(t)
	for name, change := range map[string]func(as *fakeAuthorizationServer){
		"private key": func(as *fakeAuthorizationServer) {
			as.keys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private, KeyID: "k0"}}}
		},
		"empty":  func(as *fakeAuthorizationServer) { as.keys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}} },
		"status": func(as *fakeAuthorizationServer) { as.jwksStatus = http.StatusFound },
	} {
		t.Run(name, func(t *testing.T) {
			as := newFakeAuthorizationServer(t, generateKey(t))
			as.set(func() { change(as) })
			if _, err := newAuthorizationServerKeys(t.Context(), as.URL, as.Client(), time.Now); err == nil {
				t.Error("keys accepted")
			}
		})
	}
}

// fakeClock is a clock the test moves.
type fakeClock struct{ now atomic.Pointer[time.Time] }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	now := time.Now()
	c.now.Store(&now)
	return c
}

func (c *fakeClock) Now() time.Time { return *c.now.Load() }

func (c *fakeClock) advance(d time.Duration) {
	next := c.Now().Add(d)
	c.now.Store(&next)
}

// servers.md rule 8 and the authorization server's key rotation: a token naming a kid the set does not hold makes
// zaddy fetch the set once, and the rotated key verifies it; another unknown kid within the interval fetches
// nothing, since the client picks the kid; after the interval a failed fetch keeps the set in force.
func TestServerRule8_AnUnknownKidRefetchesTheKeysAtMostOncePerInterval(t *testing.T) {
	oldKey, newKey := generateKey(t), generateKey(t)
	as := newFakeAuthorizationServer(t, oldKey)
	clock := newFakeClock()
	keys, err := newAuthorizationServerKeys(t.Context(), as.URL, as.Client(), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pep.NewBuilder().Resource("https://rs.example").WithKeySource(keys).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyAccessToken(accessToken(t, oldKey, "k0")); err != nil || as.jwksFetches.Load() != 1 {
		t.Fatalf("old key: %v, %d fetches", err, as.jwksFetches.Load())
	}

	as.setKeys(oldKey, newKey)
	clock.advance(keysRefetchInterval)
	if _, err := p.VerifyAccessToken(accessToken(t, newKey, "k1")); err != nil || as.jwksFetches.Load() != 2 {
		t.Fatalf("rotated key: %v, %d fetches", err, as.jwksFetches.Load())
	}

	clock.advance(keysRefetchInterval / 2)
	if _, err := p.VerifyAccessToken(accessToken(t, newKey, "unknown")); err == nil || as.jwksFetches.Load() != 2 {
		t.Fatalf("second unknown kid within the interval: %v, %d fetches", err, as.jwksFetches.Load())
	}

	clock.advance(keysRefetchInterval)
	as.set(func() { as.jwksStatus = http.StatusServiceUnavailable })
	if _, err := p.VerifyAccessToken(accessToken(t, newKey, "unknown")); err == nil || as.jwksFetches.Load() != 3 {
		t.Fatalf("failed refetch: %v, %d fetches", err, as.jwksFetches.Load())
	}
	for kid, key := range map[string]*ecdsa.PrivateKey{"k0": oldKey, "k1": newKey} {
		if _, err := p.VerifyAccessToken(accessToken(t, key, kid)); err != nil {
			t.Errorf("%s after a failed refetch: %v", kid, err)
		}
	}
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
	mismatched.metadata = func(issuer string) string {
		return fmt.Sprintf(`{"issuer":"https://as.example","jwks_uri":%q}`, issuer+"/jwks")
	}
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

// The background refresh ends with the app: Stop cancels it.
func TestAuthorizationServerKeysRefreshStopsWithTheApp(t *testing.T) {
	as := newFakeAuthorizationServer(t, generateKey(t))
	keys, err := newAuthorizationServerKeys(t.Context(), as.URL, as.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		keys.run(ctx, time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for as.jwksFetches.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if as.jwksFetches.Load() < 3 {
		t.Fatal("the set was not fetched in the background")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the background refresh did not stop")
	}
}
