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

package openid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	response, err := client.Exchange(t.Context(), Login{Nonce: "n", Verifier: "verifier"}, "code")
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
			if _, err := client.Exchange(t.Context(), Login{Nonce: "n", Verifier: "verifier"}, "code"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestExchangeToleratesExpiryWithinTheSkew(t *testing.T) {
	stub := newOPStub(t)
	client := stub.client(t)
	stub.idToken = signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":"n","exp":%d}`, stub.URL, time.Now().Add(-defaultAcceptableSkew/2).Unix()))
	if _, err := client.Exchange(t.Context(), Login{Nonce: "n", Verifier: "verifier"}, "code"); err != nil {
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
	if !strings.Contains(authURL, "code_challenge="+S256Challenge("verifier")) || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("url = %s", authURL)
	}
}

// serveDiscovery serves doc as the provider metadata at the root of a test server; doc is given the server's URL.
func serveDiscovery(t *testing.T, status int, doc func(base string) DiscoveryDocument) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: newECKey(t, elliptic.P256()).Public(), KeyID: "k"}}}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(keys)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(doc(server.URL))
	}))
	t.Cleanup(server.Close)
	return server
}

// OpenID Connect Discovery 1.0 section 4.3: the issuer in the document must be exactly the one it was asked of, or a
// provider could speak for another.
func TestDiscovery4_3_ADocumentNamingAnotherIssuerIsRefused(t *testing.T) {
	server := serveDiscovery(t, http.StatusOK, func(base string) DiscoveryDocument {
		return DiscoveryDocument{Issuer: "https://evil.example", JwksURI: base + "/jwks"}
	})
	_, err := NewClient(Config{Issuer: server.URL, HTTPClient: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "https://evil.example") {
		t.Errorf("err = %v", err)
	}
}

func TestDiscovery4_3_ADocumentWithoutAnIssuerIsRefused(t *testing.T) {
	server := serveDiscovery(t, http.StatusOK, func(base string) DiscoveryDocument {
		return DiscoveryDocument{JwksURI: base + "/jwks"}
	})
	if _, err := NewClient(Config{Issuer: server.URL, HTTPClient: server.Client()}); err == nil {
		t.Error("accepted")
	}
}

// A multi-tenant Entra document names the issuer {tenantid}, which no ID token ever carries, so such a configuration
// could not log anybody in: it is refused at the start, without an exception for the placeholder.
func TestDiscovery4_3_EntrasTenantPlaceholderIsRefusedLikeAnyOtherIssuer(t *testing.T) {
	server := serveDiscovery(t, http.StatusOK, func(base string) DiscoveryDocument {
		return DiscoveryDocument{Issuer: "https://login.microsoftonline.com/{tenantid}/v2.0", JwksURI: base + "/jwks"}
	})
	if _, err := NewClient(Config{Issuer: server.URL + "/common/v2.0", HTTPClient: server.Client()}); err == nil {
		t.Error("accepted")
	}
}

func TestDiscoveryAFailureStatusIsRefusedHoweverItsBodyReads(t *testing.T) {
	server := serveDiscovery(t, http.StatusServiceUnavailable, func(base string) DiscoveryDocument {
		return DiscoveryDocument{Issuer: base, JwksURI: base + "/jwks"}
	})
	if _, err := NewClient(Config{Issuer: server.URL, HTTPClient: server.Client()}); err == nil {
		t.Error("accepted")
	}
}

// Section 4.1: a terminating / is removed before the path is appended, while the comparison stays exact.
func TestDiscovery4_1_AnIssuerWithATrailingSlashIsFetchedWithoutItAndComparedWithIt(t *testing.T) {
	var server *httptest.Server
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: newECKey(t, elliptic.P256()).Public(), KeyID: "k"}}}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: server.URL + "/", JwksURI: server.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(keys)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{Issuer: server.URL + "/", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if client.Issuer() != server.URL+"/" {
		t.Errorf("issuer = %s", client.Issuer())
	}
}

func TestDiscoveryReadsNoMoreThanItsBound(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"padding":"`, server.URL, server.URL+"/jwks")
		for range maxResponseBytes / 1024 {
			_, _ = w.Write(make([]byte, 1024))
		}
		fmt.Fprint(w, `"}`)
	}))
	defer server.Close()
	_, err := NewClient(Config{Issuer: server.URL, HTTPClient: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func TestClaimsRefusesATokenThatIsNoCompactJWS(t *testing.T) {
	for _, token := range []string{"nodots", "one.dot", "a.b.c.d"} {
		var claims map[string]any
		if err := (&TokenResponse{IDTokenRaw: token}).Claims(&claims); err == nil {
			t.Errorf("%q accepted", token)
		}
	}
}

func captureDebugLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// Server rules 5 and 14. The provider's refusal echoes the code, as nothing stops one from doing.
func TestALoginLogsNoSecretAtDebug(t *testing.T) {
	const (
		secret, state, nonce  = "client-secret-value", "state-value", "nonce-value"
		verifier, code, token = "verifier-value", "code-value", "access-token-value"
		refresh               = "refresh-token-value"
	)
	mux := http.NewServeMux()
	stub := &opStub{key: newECKey(t, elliptic.P256())}
	publicKey := jose.JSONWebKey{Key: stub.key.Public(), KeyID: "k"}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: stub.URL, AuthorizationEndpoint: stub.URL + "/authorize", TokenEndpoint: stub.URL + "/token", JwksURI: stub.URL + "/jwks"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicKey}})
	})
	refuse := false
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		if refuse {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "no such code: " + code})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "refresh_token": refresh, "token_type": "Bearer", "id_token": stub.idToken})
	})
	stub.Server = httptest.NewServer(mux)
	defer stub.Close()

	logs := captureDebugLogs(t)
	client, err := NewClient(Config{Issuer: stub.URL, ClientID: "client", ClientSecret: NewSecretString(secret), RedirectURI: "https://rp.example/cb", Scopes: []string{"openid"}, HTTPClient: stub.Client()})
	if err != nil {
		t.Fatal(err)
	}
	stub.idToken = signToken(t, jose.ES256, stub.key, "k", fmt.Appendf(nil, `{"iss":%q,"aud":"client","nonce":%q,"exp":%d}`, stub.URL, nonce, time.Now().Add(time.Hour).Unix()))
	login := Login{State: state, Nonce: nonce, Verifier: verifier}
	if _, err := client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), login, code); err != nil {
		t.Fatal(err)
	}
	refuse = true
	if _, err := client.Exchange(t.Context(), login, code); err == nil {
		t.Fatal("the refusal went unnoticed")
	}
	for _, value := range []string{secret, state, nonce, verifier, code, token, refresh, stub.idToken} {
		if strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs)
		}
	}
}

// A slog handler for JSON goes through MarshalJSON and one for text through String, and neither may show the secret.
func TestSecretStringShowsNothingInLogsOrJSON(t *testing.T) {
	const value = "client-secret-value"
	secret := NewSecretString(value)
	var logs bytes.Buffer
	holder := struct{ ClientSecret SecretString }{secret}
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "secret", secret, "holder", holder)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "secret", secret, "holder", holder)
	if strings.Contains(logs.String(), value) {
		t.Errorf("logged: %s", logs.String())
	}
	marshalled, err := json.Marshal(holder)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marshalled), value) {
		t.Errorf("marshalled: %s", marshalled)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v %s", holder, holder, holder, secret), value) {
		t.Error("formatted")
	}
	if secret.Value() != value {
		t.Errorf("value = %q", secret.Value())
	}
}

// A key file whose d is not the private half of its x and y signs what its published key does not verify, which go-jose
// lets through and only the first token would show.
func TestParseKeyRefusesAnECKeyWhoseDIsNotThePrivateHalfOfItsPoint(t *testing.T) {
	one, other := newECKey(t, elliptic.P256()), newECKey(t, elliptic.P256())
	data, err := json.Marshal(jose.JSONWebKey{Key: one})
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(data); err != nil {
		t.Fatalf("a good key: %v", err)
	}
	otherData, err := json.Marshal(jose.JSONWebKey{Key: other})
	if err != nil {
		t.Fatal(err)
	}
	var otherMembers map[string]any
	if err := json.Unmarshal(otherData, &otherMembers); err != nil {
		t.Fatal(err)
	}
	members["d"] = otherMembers["d"]
	mixed, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseKey(mixed)
	if err == nil {
		t.Fatal("accepted")
	}
	if d, _ := members["d"].(string); strings.Contains(err.Error(), d) {
		t.Errorf("the error shows d: %v", err)
	}
}
