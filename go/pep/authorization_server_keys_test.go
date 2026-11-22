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

package pep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
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
	as := &fakeAuthorizationServer{metadataPath: AuthorizationServerMetadataPath, jwksStatus: http.StatusOK}
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
			if _, err := fetchedKeys(t, as, time.Now); err == nil {
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
	as.metadataPath = OpenIDConfigurationPath
	keys, err := fetchedKeys(t, as, time.Now)
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
		if got, err := AuthorizationServerMetadataURL(issuer); err != nil || got != want {
			t.Errorf("%s: %q, %v", issuer, got, err)
		}
	}
	for _, issuer := range []string{"http://as.example", "https://as.example?x=1", "https://as.example#f", "https://u@as.example", "as.example"} {
		if got, err := AuthorizationServerMetadataURL(issuer); err == nil {
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
			if _, err := fetchedKeys(t, as, time.Now); err == nil {
				t.Error("keys accepted")
			}
		})
	}
}

// fetchedKeys are the keys of as after their first fetch, or the fetch's error.
func fetchedKeys(t *testing.T, as *fakeAuthorizationServer, now func() time.Time) (*AuthorizationServerKeys, error) {
	t.Helper()
	keys, err := NewAuthorizationServerKeys(AuthorizationServerKeysConfig{Issuer: as.URL, HTTPClient: as.Client(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Fetch(t.Context()); err != nil {
		return nil, err
	}
	return keys, nil
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
	keys, err := fetchedKeys(t, as, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewBuilder().Resource("https://rs.example").WithKeySource(keys).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyAccessToken(accessToken(t, oldKey, "k0")); err != nil || as.jwksFetches.Load() != 1 {
		t.Fatalf("old key: %v, %d fetches", err, as.jwksFetches.Load())
	}

	as.setKeys(oldKey, newKey)
	clock.advance(DefaultKeysRefetchInterval)
	if _, err := p.VerifyAccessToken(accessToken(t, newKey, "k1")); err != nil || as.jwksFetches.Load() != 2 {
		t.Fatalf("rotated key: %v, %d fetches", err, as.jwksFetches.Load())
	}

	clock.advance(DefaultKeysRefetchInterval / 2)
	if _, err := p.VerifyAccessToken(accessToken(t, newKey, "unknown")); err == nil || as.jwksFetches.Load() != 2 {
		t.Fatalf("second unknown kid within the interval: %v, %d fetches", err, as.jwksFetches.Load())
	}

	clock.advance(DefaultKeysRefetchInterval)
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

// The configuration takes an issuer identifier and the host's client; before the first fetch there are no keys, so
// every token is refused.
func TestRFC8414_2_AuthorizationServerKeysNeedAnIssuerAndAClient(t *testing.T) {
	for name, config := range map[string]AuthorizationServerKeysConfig{
		"http issuer":  {Issuer: "http://as.example", HTTPClient: http.DefaultClient},
		"query":        {Issuer: "https://as.example?a=b", HTTPClient: http.DefaultClient},
		"no client":    {Issuer: "https://as.example"},
		"negative gap": {Issuer: "https://as.example", HTTPClient: http.DefaultClient, RefetchInterval: -time.Second},
	} {
		if _, err := NewAuthorizationServerKeys(config); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	keys, err := NewAuthorizationServerKeys(AuthorizationServerKeysConfig{Issuer: "https://as.example", HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if set, err := keys.Keys(); err == nil || set != nil {
		t.Error("keys before the first fetch")
	}
}

// servers.md rule 28, limits before work: a fetched document nested too deep, with too many members or a member
// named twice is refused before it is decoded.
func TestServerRule28_AFetchedDocumentIsBoundedBeforeItIsDecoded(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxFetchedDepth+1) + "1" + strings.Repeat("}", maxFetchedDepth+1)
	var many strings.Builder
	many.WriteString("{")
	for i := range maxFetchedMembers + 1 {
		if i > 0 {
			many.WriteString(",")
		}
		fmt.Fprintf(&many, `"m%d":1`, i)
	}
	many.WriteString("}")
	for name, doc := range map[string]string{
		"deep": deep, "many members": many.String(), "duplicate": `{"a":1,"a":2}`, "array": `[1]`,
		"trailing data": `{"a":1} {}`, "not UTF-8": "{\"a\":\"\xff\"}",
	} {
		if err := checkJSONObject([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkJSONObject([]byte(`{"keys":[{"kty":"EC","x5c":["a"]}]}`)); err != nil {
		t.Error(err)
	}
}
