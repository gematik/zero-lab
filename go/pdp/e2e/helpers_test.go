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

	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Defaults for the e2e knobs; overridable via the matching ZERO_PDP_E2E_* env vars.
const (
	defaultClientID      = "e2e-client"
	defaultClientKeyPath = "testdata/e2e-client.prk.jwk"
	defaultScope         = "e2e"
	defaultOPIssuer      = "https://accounts.google.com"
	defaultFedIssuer     = "https://idbroker.tk.ru2.nonprod-ehealth-id.de"
	defaultRedirectURI   = "http://localhost:8765/as-callback"
	defaultCallbackAddr  = "localhost:8765"
)

// clientKey loads the e2e client's private signing JWK (its public half is registered in the AS
// config), used to mint private_key_jwt assertions. Override with ZERO_PDP_E2E_CLIENT_KEY_PATH.
func clientKey(t *testing.T) jwk.Key {
	t.Helper()
	path := env("ZERO_PDP_E2E_CLIENT_KEY_PATH", defaultClientKeyPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read client key %s: %v", path, err)
	}
	k, err := jwk.ParseKey(b)
	if err != nil {
		t.Fatalf("parse client key: %v", err)
	}
	return k
}

// clientAssertion mints a private_key_jwt assertion (RFC 7523) for clientID signed with key: a fresh
// AS nonce, iss=sub=clientID, aud=issuer, and cnf.jkt = key's thumbprint.
func clientAssertion(t *testing.T, md authzserver.ExtendedMetadata, clientID string, key jwk.Key) string {
	t.Helper()
	resp := mustGet(t, httpClient(), md.NonceEndpoint)
	nonceBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	nonce := strings.TrimSpace(string(nonceBytes))

	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	now := time.Now()
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, clientID)
	tok.Set(jwt.SubjectKey, clientID)
	tok.Set(jwt.AudienceKey, md.Issuer)
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Minute).Unix())
	tok.Set("nonce", nonce)
	tok.Set("cnf", map[string]string{"jkt": base64.RawURLEncoding.EncodeToString(thumb)})
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return string(signed)
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

// noRedirectClient returns a client that does not follow redirects (so 3xx Location can be
// inspected).
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

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

func getJWKS(t *testing.T, md authzserver.ExtendedMetadata) jwk.Set {
	t.Helper()
	resp := mustGet(t, httpClient(), md.JwksURI)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: status %d", resp.StatusCode)
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		t.Fatalf("jwks: parse: %v", err)
	}
	return set
}

// verifyAccessToken parses and signature-verifies an access token against the server JWKS.
func verifyAccessToken(t *testing.T, raw string, keys jwk.Set) jwt.Token {
	t.Helper()
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(keys, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("access token did not verify against JWKS: %v", err)
	}
	return tok
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
	cb.srv = &http.Server{Handler: mux}
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
