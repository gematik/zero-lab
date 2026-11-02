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

package e2e

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// Defaults for the e2e knobs; overridable via the matching ZERO_PDP_E2E_* env vars.
const (
	defaultClientID      = "e2e-client"
	defaultClientKeyPath = "testdata/e2e-client.prk.jwk"
	defaultScope         = "e2e"
	defaultIDPIss        = "https://accounts.google.com"
	defaultFedIssuer     = "https://idbroker.tk.ru2.nonprod-ehealth-id.de"
	defaultRedirectURI   = "http://localhost:8765/as-callback"
	defaultCallbackAddr  = "localhost:8765"
)

// clientKey loads the e2e client's private signing JWK (its public half is registered in the AS
// config), used to mint private_key_jwt assertions. Override with ZERO_PDP_E2E_CLIENT_KEY_PATH.
func clientKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	path := env("ZERO_PDP_E2E_CLIENT_KEY_PATH", defaultClientKeyPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read client key %s: %v", path, err)
	}
	k, err := oidc.ParseKey(b)
	if err != nil {
		t.Fatalf("parse client key: %v", err)
	}
	return k
}

// clientAssertion mints a private_key_jwt assertion (RFC 7523) for clientID signed with key: a fresh
// AS nonce, iss=sub=clientID, aud=issuer, and cnf.jkt = key's thumbprint.
func clientAssertion(t *testing.T, md authzserver.ExtendedMetadata, clientID string, key *jose.JSONWebKey) string {
	t.Helper()
	resp := mustGet(t, httpClient(), md.NonceEndpoint)
	nonceBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	nonce := strings.TrimSpace(string(nonceBytes))

	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss":   clientID,
		"sub":   clientID,
		"aud":   []string{md.Issuer},
		"iat":   now.Unix(),
		"exp":   now.Add(time.Minute).Unix(),
		"nonce": nonce,
		"cnf":   map[string]string{"jkt": base64.RawURLEncoding.EncodeToString(thumb)},
	})
	if err != nil {
		t.Fatalf("encode claims: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	signed, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize assertion: %v", err)
	}
	return signed
}

// signDPoP adds a DPoP proof for req signed by key, the key clientAssertion names as cnf.jkt: RFC 9449
// Section 5 requires a proof on every token request whose tokens are DPoP-bound.
func signDPoP(t *testing.T, req *http.Request, key *jose.JSONWebKey) {
	t.Helper()
	signer, ok := key.Key.(crypto.Signer)
	if !ok {
		t.Fatalf("key %T is not a private key", key.Key)
	}
	dpopKey, err := dpop.NewKeyFromSigner(signer)
	if err != nil {
		t.Fatalf("dpop key: %v", err)
	}
	if err := dpopKey.Sign(req, dpop.ProofOptions{}); err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
}

// addClientAuth adds the private_key_jwt parameters to a token/introspection form.
func addClientAuth(form url.Values, assertion string) {
	form.Set("client_assertion_type", authzserver.ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
}

// baseURL returns the e2e target base URL, skipping the test if ZERO_PDP_E2E_URL is unset.
func baseURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("ZERO_PDP_E2E_URL")
	if u == "" {
		t.Skip("ZERO_PDP_E2E_URL not set — skipping pdp e2e test (see docs/e2e.md)")
	}
	return strings.TrimRight(u, "/")
}

// env returns the env var or a default.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func httpClient() *http.Client { return &http.Client{Timeout: 20 * time.Second} }

// getMetadata fetches and decodes the RFC 8414 authorization-server metadata.
func getMetadata(t *testing.T, base string) authzserver.ExtendedMetadata {
	t.Helper()
	var md authzserver.ExtendedMetadata
	resp := mustGet(t, httpClient(), base+"/.well-known/oauth-authorization-server")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("metadata: decode: %v", err)
	}
	return md
}

// openidProvider is the subset of /openid_providers we care about.
type openidProvider struct {
	Issuer string `json:"iss"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

func getOpenidProviders(t *testing.T, md authzserver.ExtendedMetadata) []openidProvider {
	t.Helper()
	var providers []openidProvider
	resp := mustGet(t, httpClient(), md.OpenidProvidersEndpoint)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("openid_providers: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		t.Fatalf("openid_providers: decode: %v", err)
	}
	return providers
}

func getJWKS(t *testing.T, md authzserver.ExtendedMetadata) *jose.JSONWebKeySet {
	t.Helper()
	resp := mustGet(t, httpClient(), md.JwksURI)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("jwks: read: %v", err)
	}
	set, err := oidc.ParseKeySet(body)
	if err != nil {
		t.Fatalf("jwks: parse: %v", err)
	}
	return set
}

// verifyAccessToken parses and signature-verifies an access token against the server JWKS.
func verifyAccessToken(t *testing.T, raw string, keys *jose.JSONWebKeySet) []byte {
	t.Helper()
	payload, err := oidc.VerifyJWS([]byte(raw), keys, oidc.VerifyOptions{})
	if err != nil {
		t.Fatalf("access token did not verify against JWKS: %v", err)
	}
	if err := oidc.ValidateLifetime(payload, time.Now(), 0); err != nil {
		t.Fatalf("access token is not valid now: %v", err)
	}
	return payload
}

func mustGet(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// pkce returns a PKCE verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// callbackResult is what the capture server records.
type callbackResult struct {
	Code  string
	State string
	Error string
	Desc  string
}

// callbackServer is a tiny HTTP listener acting as the test client's redirect_uri.
type callbackServer struct {
	srv         *http.Server
	redirectURI string
	results     chan callbackResult
}

// startCallbackServer starts a capture server on a fixed address so its URL can be a stable,
// pre-registered redirect_uri. addr is host:port (e.g. "localhost:8765").
func startCallbackServer(t *testing.T, addr string) *callbackServer {
	t.Helper()
	cb := &callbackServer{results: make(chan callbackResult, 1)}
	mux := http.NewServeMux()
	// Catch-all so the captured redirect path doesn't have to be hardcoded.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		cb.results <- callbackResult{
			Code: q.Get("code"), State: q.Get("state"),
			Error: q.Get("error"), Desc: q.Get("error_description"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("received — you can close this tab and return to the test"))
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("callback server listen on %s: %v", addr, err)
	}
	cb.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = cb.srv.Serve(ln) }()
	cb.redirectURI = "http://" + addr + "/as-callback"
	t.Cleanup(func() { _ = cb.srv.Close() })
	return cb
}

// wait blocks for the captured callback or fails after the timeout.
func (cb *callbackServer) wait(t *testing.T, timeout time.Duration) callbackResult {
	t.Helper()
	select {
	case res := <-cb.results:
		return res
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for the OP callback — was the browser login completed?", timeout)
		return callbackResult{}
	}
}

// hostOf returns the host of a URL, for asserting redirect targets.
func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u.Host
}
