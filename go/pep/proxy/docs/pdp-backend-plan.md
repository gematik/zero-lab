# S4 — pep PDP Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `pdpBackend` to pep so it logs in as a confidential BFF client of the PDP, holds DPoP-bound tokens server-side, and injects them into a gated `/api` reverse-proxy — proven end-to-end against the airgapped `zero-pdp` (mock IdP) + a `zaddy` resource server that verifies the DPoP proof.

**Architecture:** Design is fixed in [`pdp-backend.md`](pdp-backend.md) — this plan only realizes it. `pdpBackend` ports the bff AS-client (`go/bff/bff.go`); DPoP proofs are minted **per session** behind a `sessionSigner` seam; one gated `/api` route reverse-proxies a single configured upstream with `Authorization: DPoP <token>` + proof (port `go/bff/gateway/inject.go`). `PEP_BACKEND=pdp` selects it, mutually exclusive with `providerBackend`.

**Tech Stack:** Go (stdlib `net/http`, `net/http/httputil`), `github.com/lestrrat-go/jwx/v3/jwk`, `golang.org/x/oauth2`, the repo's `go/dpop` package, `segmentio/ksuid`.

## Global Constraints

- Module path `github.com/gematik/zero-lab/go`. Reuse `go/dpop` for proofs (`dpop.NewBuilder()...Build().Sign()`, `dpop.FromJWK`, `dpop.NewPrivateKey`, `dpop.DPoPHeaderName`, `dpop.CalculateAccessTokenHash`).
- The design doc is authoritative for *what*: read [`pdp-backend.md`](pdp-backend.md) §§2–8, 12 before each task.
- Secrets via `*_PATH` files only — never env values, never in `kv`.
- DPoP proof binds `htm`/`htu` to the **actual outbound request**, `ath = SHA256(access_token)`; signed with the **session** DPoP key (S4 holds it; §4 of the spec). `cnf.jkt` in the `private_key_jwt` assertion = the **session** DPoP-key thumbprint.
- `PEP_BACKEND=pdp` is mutually exclusive with the provider backend.
- BCP allowlist MUST: the `/api` proxy forwards only to the one configured upstream host.
- Tests: table-driven, `httptest`, in-memory store via `kv.NewMemory()`, call handler/backend methods directly (match `pep/proxy/*_test.go`).
- Module graph unchanged: `go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|kv\|oauth\|pep/proxy\)'` stays `0`.
- Commits: conventional, no AI attribution. Branch `feat/pep-pdp-backend`.

## File Structure

- **Modify** `pep/proxy/session.go` — add a per-AS token set + the session DPoP key (+ accessors).
- **Create** `pep/proxy/signer.go` — `sessionSigner` interface + the BFF-held-key impl + DPoP proof minting.
- **Create** `pep/proxy/signer_test.go`.
- **Create** `pep/proxy/backend_pdp.go` — `pdpBackend` (ported AS-client) implementing `Backend`.
- **Create** `pep/proxy/backend_pdp_test.go`.
- **Create** `pep/proxy/inject.go` — the gated `/api` reverse-proxy + DPoP injection (port of `bff/gateway/inject.go`).
- **Create** `pep/proxy/inject_test.go`.
- **Modify** `pep/proxy/backend.go` — drop `DPoPKey()` from the `Backend` interface.
- **Modify** `pep/proxy/backend_provider.go` — drop its `DPoPKey()` method.
- **Modify** `pep/cmd/zero-pep-proxy/main.go` + a new `pep/cmd/zero-pep-proxy/backend_pdp.go` — `PEP_BACKEND=pdp` selection + the binding config.
- **Modify** `pep/proxy/e2e/` (compose + README) — the airgapped HITL composing pep(pdp) + zero-pdp + zaddy.

---

### Task 1: Session — per-AS token set + session DPoP key

**Files:** Modify `pep/proxy/session.go`; Test `pep/proxy/session_test.go` (create if absent).

**Interfaces:**
- Produces: `Session.Tokens map[string]*TokenEntry` (keyed by AS issuer), `Session.DPoPKeyJWK []byte` (the session DPoP private key, JSON-marshaled JWK), and helpers `func (s *Session) SetTokens(asIssuer string, e *TokenEntry)` / `func (s *Session) GetTokens(asIssuer string) (*TokenEntry, bool)`. `type TokenEntry struct { AccessToken, RefreshToken string; ExpiresAt time.Time }`.

- [ ] **Step 1: Write the failing test**

Add to `pep/proxy/session_test.go`:

```go
func TestSessionTokenSet(t *testing.T) {
	s := &Session{ID: "x"}
	if _, ok := s.GetTokens("https://as"); ok {
		t.Fatal("empty session should have no tokens")
	}
	s.SetTokens("https://as", &TokenEntry{AccessToken: "at", RefreshToken: "rt", ExpiresAt: time.Unix(100, 0)})
	got, ok := s.GetTokens("https://as")
	if !ok || got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Fatalf("got %+v, ok=%v", got, ok)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pep/proxy/ -run TestSessionTokenSet`
Expected: FAIL — `TokenEntry`/`GetTokens`/`SetTokens` undefined.

- [ ] **Step 3: Add the fields + helpers**

In `pep/proxy/session.go`, add to the `Session` struct (after `AccessTokenExpiresAt`):

```go
	// PDP backend: tokens keyed by AS issuer (one entry in S4) and the per-session DPoP private key (JWK
	// JSON). The provider backend leaves both zero. DPoPKeyJWK holds the private key in S4; the T3 stage
	// (see pdp-backend.md §10) moves it to the browser, leaving only the public half here.
	Tokens     map[string]*TokenEntry `json:"tokens,omitempty"`
	DPoPKeyJWK []byte                 `json:"dpop_key_jwk,omitempty"`
```

And below the struct:

```go
// TokenEntry is the PDP-issued token set for one authorization server.
type TokenEntry struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

func (s *Session) SetTokens(asIssuer string, e *TokenEntry) {
	if s.Tokens == nil {
		s.Tokens = map[string]*TokenEntry{}
	}
	s.Tokens[asIssuer] = e
}

func (s *Session) GetTokens(asIssuer string) (*TokenEntry, bool) {
	e, ok := s.Tokens[asIssuer]
	return e, ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pep/proxy/ -run TestSessionTokenSet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/session.go pep/proxy/session_test.go
git commit -m "feat(pep): per-AS token set + session DPoP key on the session"
```

---

### Task 2: sessionSigner seam + DPoP proof minting

**Files:** Create `pep/proxy/signer.go`, `pep/proxy/signer_test.go`.

**Interfaces:**
- Produces: `type sessionSigner interface { dpopProof(req *http.Request, accessToken string, key jwk.Key) (string, error) }`; `type bffSigner struct{}` implementing it; `func newSessionDPoPKey() (priv jwk.Key, jwkJSON []byte, err error)`; `func parseSessionDPoPKey(jwkJSON []byte) (jwk.Key, error)`.
- Consumes: `go/dpop` (`dpop.NewPrivateKey`, `dpop.FromJWK`, builder).

- [ ] **Step 1: Write the failing test**

`pep/proxy/signer_test.go`:

```go
package proxy

import (
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/dpop"
)

func TestBffSignerProof(t *testing.T) {
	priv, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(jwkJSON) == 0 {
		t.Fatal("expected serialized key")
	}
	req, _ := http.NewRequest("GET", "https://api.example/protected", nil)
	proof, err := (bffSigner{}).dpopProof(req, "the-access-token", priv)
	if err != nil {
		t.Fatalf("dpopProof: %v", err)
	}
	parsed, err := dpop.Parse(proof)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	if parsed.HttpMethod != "GET" || parsed.HttpURI != "https://api.example/protected" {
		t.Errorf("htm/htu = %s %s", parsed.HttpMethod, parsed.HttpURI)
	}
	ath, _ := dpop.CalculateAccessTokenHash("the-access-token")
	if parsed.AccessTokenHash != ath {
		t.Errorf("ath = %q, want %q", parsed.AccessTokenHash, ath)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestBffSignerProof`
Expected: FAIL — undefined `newSessionDPoPKey` / `bffSigner`.

- [ ] **Step 3: Implement**

`pep/proxy/signer.go`:

```go
package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// sessionSigner mints the DPoP proof for an outbound API request. S4's implementation (bffSigner) signs with
// the session's BFF-held key; the T3 stage (pdp-backend.md §10) swaps in a browser-relaying signer.
type sessionSigner interface {
	dpopProof(req *http.Request, accessToken string, key jwk.Key) (string, error)
}

type bffSigner struct{}

func (bffSigner) dpopProof(req *http.Request, accessToken string, key jwk.Key) (string, error) {
	pk, err := dpop.FromJWK(key)
	if err != nil {
		return "", fmt.Errorf("wrap dpop key: %w", err)
	}
	tok, err := dpop.NewBuilder().HttpRequest(req).AccessTokenHashFrom(accessToken).Build()
	if err != nil {
		return "", fmt.Errorf("build dpop proof: %w", err)
	}
	return tok.Sign(pk)
}

// newSessionDPoPKey generates a per-session DPoP keypair and returns the private key + its JSON-marshaled JWK
// for storage on the session.
func newSessionDPoPKey() (jwk.Key, []byte, error) {
	pk, err := dpop.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	js, err := json.Marshal(pk.JwkPrivate)
	if err != nil {
		return nil, nil, err
	}
	return pk.JwkPrivate, js, nil
}

func parseSessionDPoPKey(jwkJSON []byte) (jwk.Key, error) {
	return jwk.ParseKey(jwkJSON)
}
```

> Verify against `go/dpop`: `dpop.PrivateKey.JwkPrivate` is the field name (the recon shows it). If `Build()` needs `AccessTokenHashFrom` to come before `Build()`, the order above matches `dpop/client.go`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pep/proxy/ -run TestBffSignerProof`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/signer.go pep/proxy/signer_test.go
git commit -m "feat(pep): sessionSigner seam + per-session DPoP proof minting"
```

---

### Task 3: pdpBackend — config, discovery, client assertion, nonce

**Files:** Create `pep/proxy/backend_pdp.go`, `pep/proxy/backend_pdp_test.go`. Read `go/bff/bff.go` first (port targets: `discoverMetadata`, `fetchNonce`, `clientAssertion`).

**Interfaces:**
- Produces: `type PDPConfig struct { ASIssuer, ClientID string; SigningKey jwk.Key; RedirectURI string; Scopes []string; APIPrefix, APIUpstream string; HTTPClient *http.Client }`; `type pdpBackend struct {...}`; `func NewPDPBackend(cfg PDPConfig) (Backend, error)`; internal `asMetadata` struct + `(b *pdpBackend) clientAssertion(ctx, sess *Session) (string, error)`.

- [ ] **Step 1: Read the bff source**

Read `go/bff/bff.go`: `discoverMetadata(issuer)` (RFC 8414 fetch into an `asMetadata` with `TokenEndpoint`, `IntrospectionEndpoint`, `AuthorizationEndpoint`, `nonce_endpoint`, `openid_providers` URL), `fetchNonce(ctx)` (GET the AS nonce endpoint, plain-text body), and `clientAssertion(ctx)` (RFC 7523 JWT: `iss=sub=client_id`, `aud=issuer`, `jti`, `iat`/`exp`, `nonce`, `cnf.jkt`). Note the exact JSON field tags + the jwx signing call.

- [ ] **Step 2: Write the failing test (client assertion claims)**

`pep/proxy/backend_pdp_test.go`:

```go
package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func testSigningKey(t *testing.T) jwk.Key {
	t.Helper()
	prk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, _ := jwk.Import(prk)
	k.Set(jwk.KeyIDKey, "test-pep-client")
	return k
}

func TestPDPClientAssertionClaims(t *testing.T) {
	b := &pdpBackend{cfg: PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t)},
		meta: asMetadata{NonceEndpoint: ""}} // empty nonce endpoint → skip nonce
	priv, jwkJSON, _ := newSessionDPoPKey()
	_ = priv
	sess := &Session{ID: "s1", DPoPKeyJWK: jwkJSON}

	assertion, err := b.clientAssertion(context.Background(), sess)
	if err != nil {
		t.Fatalf("clientAssertion: %v", err)
	}
	pub, _ := b.cfg.SigningKey.PublicKey()
	tok, err := jwt.Parse([]byte(assertion), jwt.WithKey(jwkAlg(t, pub), pub))
	if err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	if iss, _ := tok.Issuer(); iss != "pep-client" {
		t.Errorf("iss = %q", iss)
	}
	var cnf map[string]any
	if err := tok.Get("cnf", &cnf); err != nil {
		t.Fatalf("no cnf: %v", err)
	}
	if cnf["jkt"] == "" || cnf["jkt"] == nil {
		t.Errorf("cnf.jkt missing: %v", cnf)
	}
}
```

(Add a small `jwkAlg` helper that returns `jwa.ES256()` for an EC P-256 key, mirroring how `pdp/authzserver` tests choose the alg.)

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestPDPClientAssertionClaims`
Expected: FAIL — `pdpBackend` / `PDPConfig` / `asMetadata` undefined.

- [ ] **Step 4: Implement config, struct, discovery, nonce, clientAssertion**

Create `pep/proxy/backend_pdp.go` porting `bff/bff.go`. The struct + config + `clientAssertion` (the security-critical part) shown here; `discoverMetadata`/`fetchNonce` are direct ports of the bff functions (same JSON tags, same HTTP calls):

```go
package proxy

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
)

const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type PDPConfig struct {
	ASIssuer    string
	ClientID    string
	SigningKey  jwk.Key // private_key_jwt signing key (from a *_PATH file)
	RedirectURI string
	Scopes      []string
	APIPrefix   string // default /api
	APIUpstream string // single allowlisted upstream
	HTTPClient  *http.Client
}

type asMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	NonceEndpoint         string `json:"nonce_endpoint"`
	OpenidProviders       string `json:"openid_providers_endpoint"`
}

type pdpBackend struct {
	cfg    PDPConfig
	meta   asMetadata
	http   *http.Client
	signer sessionSigner
}

func NewPDPBackend(cfg PDPConfig) (Backend, error) {
	if cfg.ASIssuer == "" || cfg.ClientID == "" || cfg.SigningKey == nil {
		return nil, fmt.Errorf("pdp backend: as_issuer, client_id, signing key required")
	}
	if cfg.APIPrefix == "" {
		cfg.APIPrefix = "/api"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	b := &pdpBackend{cfg: cfg, http: hc, signer: bffSigner{}}
	meta, err := b.discoverMetadata(cfg.ASIssuer) // port of bff discoverMetadata (RFC 8414)
	if err != nil {
		return nil, fmt.Errorf("pdp discovery: %w", err)
	}
	b.meta = meta
	return b, nil
}

// clientAssertion mints a private_key_jwt (RFC 7523 §2.2) binding the token to the SESSION's DPoP key via
// cnf.jkt. Port of bff clientAssertion, adapted: the thumbprint comes from the session key, not a process key.
func (b *pdpBackend) clientAssertion(ctx context.Context, sess *Session) (string, error) {
	dkey, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return "", fmt.Errorf("session dpop key: %w", err)
	}
	thumb, err := dkey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, b.cfg.ClientID)
	tok.Set(jwt.SubjectKey, b.cfg.ClientID)
	tok.Set(jwt.AudienceKey, b.cfg.ASIssuer)
	tok.Set(jwt.JwtIDKey, ksuid.New().String())
	tok.Set(jwt.IssuedAtKey, time.Now().Unix())
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Minute).Unix())
	tok.Set("cnf", map[string]string{"jkt": jkt})
	if b.meta.NonceEndpoint != "" {
		nonce, err := b.fetchNonce(ctx) // port of bff fetchNonce
		if err != nil {
			return "", err
		}
		tok.Set("nonce", nonce)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), b.cfg.SigningKey))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// discoverMetadata and fetchNonce: port verbatim from go/bff/bff.go (same endpoints + JSON tags). Use b.http.
func (b *pdpBackend) discoverMetadata(issuer string) (asMetadata, error) { /* port from bff */ }
func (b *pdpBackend) fetchNonce(ctx context.Context) (string, error)     { /* port from bff */ }

var _ = dpop.DPoPHeaderName // injection lands in Task 6
```

> The `discoverMetadata`/`fetchNonce` bodies are direct ports — copy from `bff/bff.go`, swap the receiver to `*pdpBackend` and the client to `b.http`. Keep their exact JSON field names so the `asMetadata` tags match the AS's metadata document (cross-check `pdp/authzserver/metadata.go`).

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./pep/proxy/ -run TestPDPClientAssertionClaims`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pep/proxy/backend_pdp.go pep/proxy/backend_pdp_test.go
git commit -m "feat(pep): pdpBackend config, discovery, private_key_jwt assertion (cnf.jkt = session key)"
```

---

### Task 4: pdpBackend — StartLogin / Complete / FreshAccessToken / Providers

**Files:** Modify `pep/proxy/backend_pdp.go`, `pep/proxy/backend_pdp_test.go`. Port targets in `bff/bff.go`: `LoginEndpoint`/`resolveDecoupledAuthURL`, the code-exchange in `CallbackEndpoint`, `introspectIdentity`, `FreshAccessToken`.

**Interfaces:**
- Produces: the remaining `Backend` methods on `pdpBackend` (`Providers`, `DefaultIssuer`, `StartLogin`, `Complete`, `FreshAccessToken`).
- Consumes: `asMetadata`, `clientAssertion` (Task 3), `newSessionDPoPKey` (Task 2), `Session.SetTokens`/`GetTokens` (Task 1).

- [ ] **Step 1: Write the failing test (StartLogin sets up the session)**

Add to `backend_pdp_test.go` a test that `StartLogin` generates the session DPoP key + PKCE/state and returns an `AuthURL` pointing at the AS authorization endpoint. Use a backend with `meta.AuthorizationEndpoint` preset and a fake `http` client (httptest) for the PAR/authorize discovery. Assert: `sess.DPoPKeyJWK != nil`, `sess.State != ""`, `sess.CodeVerifier != ""`, and `LoginStart.AuthURL` starts with the authorization endpoint.

```go
func TestPDPStartLoginPreparesSession(t *testing.T) {
	b := &pdpBackend{cfg: PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t)},
		meta: asMetadata{AuthorizationEndpoint: "https://as.example/auth"}, http: http.DefaultClient, signer: bffSigner{}}
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestPDPStartLoginPreparesSession`
Expected: FAIL — `StartLogin` not implemented on `pdpBackend`.

- [ ] **Step 3: Implement the Backend methods**

Add to `backend_pdp.go` (port the bodies from `bff/bff.go`, adapting to the `Session`/`Backend` shapes):

```go
func (b *pdpBackend) DefaultIssuer() string { return b.cfg.ASIssuer }

func (b *pdpBackend) Providers(ctx context.Context) ([]Provider, error) {
	// GET b.meta.OpenidProviders; map to []Provider{Type:"oidf"/"oidc"}. Port from bff providers fetch.
}

func (b *pdpBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		return LoginStart{}, err
	}
	sess.DPoPKeyJWK = jwkJSON
	sess.IDPIss = idpIss
	sess.State = ksuid.New().String()
	sess.Nonce = ksuid.New().String()
	sess.CodeVerifier = oauth2.GenerateVerifier()
	sess.CodeChallengeMethod = "S256"
	// Build the AS authorization request (state, nonce, PKCE challenge, redirect_uri, scope, idp_iss).
	// For OIDF the AS performs PAR → resolveDecoupledAuthURL (port from bff) returns the decoupled URL and
	// Mode "decoupled". Otherwise Mode "redirect".
	authURL, mode, err := b.authorizationURL(ctx, sess, scope)
	if err != nil {
		return LoginStart{}, err
	}
	return LoginStart{AuthURL: authURL, Mode: mode}, nil
}

func (b *pdpBackend) Complete(ctx context.Context, sess *Session, code string) error {
	assertion, err := b.clientAssertion(ctx, sess)
	if err != nil {
		return err
	}
	// POST b.meta.TokenEndpoint: grant_type=authorization_code, code, code_verifier, redirect_uri, client_id,
	// client_assertion_type, client_assertion + a DPoP header signed with the session key (port the bff
	// exchange; reuse b.signer for the DPoP header on the token request). Parse the token response.
	tr, err := b.exchange(ctx, sess, code, assertion)
	if err != nil {
		return err
	}
	sess.SetTokens(b.cfg.ASIssuer, &TokenEntry{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	})
	// Introspect the access token for identity (port bff introspectIdentity), fill sess.Identity.
	id, err := b.introspectIdentity(ctx, sess, tr.AccessToken)
	if err != nil {
		return fmt.Errorf("introspect: %w", err)
	}
	sess.Identity = id
	return nil
}

func (b *pdpBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	e, ok := sess.GetTokens(b.cfg.ASIssuer)
	if !ok {
		return "", fmt.Errorf("no token for %s", b.cfg.ASIssuer)
	}
	if time.Until(e.ExpiresAt) > 30*time.Second {
		return e.AccessToken, nil
	}
	// Refresh via b.meta.TokenEndpoint (grant_type=refresh_token + client_assertion + DPoP), persist back to
	// the session token set. Port bff FreshAccessToken. The caller (Task 6) saves the session afterwards.
	refreshed, err := b.refresh(ctx, sess, e.RefreshToken)
	if err != nil {
		return "", err
	}
	sess.SetTokens(b.cfg.ASIssuer, refreshed)
	return refreshed.AccessToken, nil
}
```

Implement the unexported helpers (`authorizationURL`, `exchange`, `introspectIdentity`, `refresh`, `resolveDecoupledAuthURL`) as ports of the corresponding `bff/bff.go` code, using `b.http`, `b.signer`, and the parsed session DPoP key. Add `import "golang.org/x/oauth2"` and `"strings"`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pep/proxy/ -run TestPDPStartLogin`
Expected: PASS. Then `go build ./pep/...` — must compile (all `Backend` methods present).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/backend_pdp.go pep/proxy/backend_pdp_test.go
git commit -m "feat(pep): pdpBackend login/exchange/introspect/refresh (Backend complete)"
```

---

### Task 5: Drop `DPoPKey()` from the Backend interface

**Files:** Modify `pep/proxy/backend.go`, `pep/proxy/backend_provider.go`, and any caller.

- [ ] **Step 1: Remove the method from the interface**

In `pep/proxy/backend.go`, delete the `DPoPKey() jwk.Key` method from `Backend` and its doc line; remove the now-unused `jwk` import if nothing else needs it.

- [ ] **Step 2: Remove providerBackend.DPoPKey**

In `pep/proxy/backend_provider.go`, delete `func (b *providerBackend) DPoPKey() jwk.Key { return nil }` and the `jwk` import if unused.

- [ ] **Step 3: Build to find callers**

Run: `go build ./pep/...`
Expected: compiles. If anything referenced `backend.DPoPKey()`, switch it to read the session key (`parseSessionDPoPKey(sess.DPoPKeyJWK)`). The recon shows `setSnapshot` does **not** use it, so there should be no caller.

- [ ] **Step 4: Run the package tests**

Run: `go test ./pep/proxy/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/backend.go pep/proxy/backend_provider.go
git commit -m "refactor(pep): drop Backend.DPoPKey() — DPoP key is per-session state"
```

---

### Task 6: Gated `/api` reverse-proxy + DPoP injection

**Files:** Create `pep/proxy/inject.go`, `pep/proxy/inject_test.go`. Add `proxyRoutes()` to `pdpBackend`. Port `bff/gateway/inject.go` (`newProxy`, the DPoP inject path).

**Interfaces:**
- Produces: `func (b *pdpBackend) apiProxy(s *Server) http.Handler` (gated reverse-proxy) and `(b *pdpBackend) proxyRoutes() []proxyRoute` returning `{Pattern: "/api/", Handler: ...}`. The handler needs the `*Server` to resolve sessions (cookie → `s.currentSession`).

> Note: `proxyRoutes()` today takes no `*Server`. Give `pdpBackend` a reference to the server, set after `New()` — add an optional `serverAware` interface (`setServer(*Server)`) that `New()` calls on the backend, or pass the session lookup as a closure. Use the closure approach to avoid touching `New()` ordering: the cmd builds the proxy handler with the store already available.

- [ ] **Step 1: Write the failing test (injection strips client auth + adds DPoP)**

`pep/proxy/inject_test.go`: stand up an httptest upstream that echoes its `Authorization` + `DPoP` headers; build a `pdpBackend` with `APIUpstream` = the upstream URL; craft a session with a DPoP key + a token; call the proxy handler with the session cookie; assert the upstream saw `Authorization: DPoP <token>` and a parseable `DPoP` proof, and that a client-supplied `Authorization: Bearer evil` was stripped.

```go
func TestAPIProxyInjectsDPoP(t *testing.T) {
	var gotAuth, gotDPoP string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get(dpop.DPoPHeaderName)
		w.WriteHeader(200)
	}))
	defer up.Close()

	priv, jwkJSON, _ := newSessionDPoPKey()
	_ = priv
	// build server with in-memory store + a saved authenticated session holding the token + key
	// (use newTestServerPDP helper — see below) ... then:
	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer evil")
	req.AddCookie(&http.Cookie{Name: srv.cookie.Name, Value: sess.ID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.HasPrefix(gotAuth, "DPoP ") || strings.Contains(gotAuth, "evil") {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if _, err := dpop.Parse(gotDPoP); err != nil {
		t.Fatalf("DPoP proof: %v", err)
	}
	_ = jwkJSON
}
```

(Provide a `newTestServerPDP(t, upstream)` helper in the test that wires `proxy.New` with a `pdpBackend`, an in-memory `kv` store, and a pre-saved authenticated session whose `DPoPKeyJWK` + `Tokens[ASIssuer]` are set; return the server, handler, and session.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestAPIProxyInjectsDPoP`
Expected: FAIL — `apiProxy`/`proxyRoutes` not implemented.

- [ ] **Step 3: Implement the injecting reverse-proxy**

`pep/proxy/inject.go` — port `bff/gateway/inject.go`'s `newProxy`, keeping the DPoP branch:

```go
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gematik/zero-lab/go/dpop"
)

// apiProxy returns a gated reverse-proxy for the binding's upstream: it requires a valid session, mints a
// fresh access token + DPoP proof (session key) per request, strips any client Authorization, and forwards.
// The upstream is the only allowed destination (BCP allowlist).
func (b *pdpBackend) apiProxy(currentSession func(*http.Request) (*Session, bool)) http.Handler {
	target, _ := url.Parse(b.cfg.APIUpstream)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, strings.TrimRight(b.cfg.APIPrefix, "/"))
			pr.Out.Header.Del("Authorization")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := currentSession(r)
		if !ok || !sess.Authenticated() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token, err := b.FreshAccessToken(r.Context(), sess)
		if err != nil || token == "" {
			http.Error(w, "no token", http.StatusBadGateway)
			return
		}
		key, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
		if err != nil {
			http.Error(w, "no key", http.StatusInternalServerError)
			return
		}
		// Build the outbound request shape for the proof: target URL + method.
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
		out.URL.Path = strings.TrimPrefix(r.URL.Path, strings.TrimRight(b.cfg.APIPrefix, "/"))
		proof, err := b.signer.dpopProof(out, token, key)
		if err != nil {
			http.Error(w, "proof", http.StatusInternalServerError)
			return
		}
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set(dpop.DPoPHeaderName, proof)
		rp.ServeHTTP(w, r)
	})
}

func (b *pdpBackend) proxyRoutes() []proxyRoute { return nil } // mounted by the cmd with the session lookup
```

> The `proxyRoute` mount needs the session lookup, which lives on `*Server`. Mount the `/api` route in the cmd (Task 7) after building the server: `mux`-wrap or use `proxy.Server`'s handler — simplest is to have the cmd compose a top-level mux: `/api/` → `pdp.apiProxy(server.CurrentSession)`, everything else → `server.Handler()`. Add an exported `func (s *Server) CurrentSession(r *http.Request) (*Session, bool) { return s.currentSession(r) }`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pep/proxy/ -run TestAPIProxyInjectsDPoP`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/inject.go pep/proxy/inject_test.go pep/proxy/proxy.go
git commit -m "feat(pep): gated /api reverse-proxy injecting Authorization: DPoP + proof"
```

---

### Task 7: Config + backend selection (`PEP_BACKEND=pdp`)

**Files:** Create `pep/cmd/zero-pep-proxy/backend_pdp.go`; Modify `pep/cmd/zero-pep-proxy/main.go`.

- [ ] **Step 1: Build the PDP backend from env**

Create `pep/cmd/zero-pep-proxy/backend_pdp.go` with `func pdpBackendFromEnv(publicURL string) (proxy.Backend, http.Handler)` reading: `PEP_AS_ISSUER`, `PEP_CLIENT_ID`, `PEP_CLIENT_SIGNING_KEY_PATH` (load the JWK from the file), `PEP_REDIRECT_URI` (default `<public>/oauth2/callback`), `PEP_API_UPSTREAM`, `PEP_API_PREFIX` (default `/api`), `PEP_SCOPES`. Construct `proxy.NewPDPBackend(proxy.PDPConfig{...})`.

- [ ] **Step 2: Wire selection in main.go**

In `main.go`, before building the provider opts: if `os.Getenv("PEP_BACKEND") == "pdp"`, build `pdpBackend` instead, and compose the top-level handler: `/api/` → the pdp api proxy, else → `server.Handler()`. Pass the pdp backend as `proxy.Config.Backend`. Keep the provider path unchanged otherwise.

- [ ] **Step 3: Build + smoke**

Run: `go build ./pep/...` then `PEP_BACKEND=pdp PEP_AS_ISSUER=... PEP_CLIENT_ID=... PEP_CLIENT_SIGNING_KEY_PATH=... PEP_API_UPSTREAM=... go run ./pep/cmd/zero-pep-proxy` against a reachable AS — expect "providers loaded"/listening (discovery succeeds). (Full flow is the HITL.)

- [ ] **Step 4: Commit**

```bash
git add pep/cmd/zero-pep-proxy/backend_pdp.go pep/cmd/zero-pep-proxy/main.go
git commit -m "feat(pep): PEP_BACKEND=pdp selection + PDP/api binding config"
```

---

### Task 8: Airgapped HITL harness + verification

**Files:** Modify `pep/proxy/e2e/docker-compose.yaml` + `README.md`; add `pep/proxy/e2e/zaddy/` config if needed.

- [ ] **Step 1: Compose the airgapped stack**

Extend the e2e compose to run (all local, no egress): `zero-pdp` (built, `PDP_NON_PROD=true`, mock IdP, in compose per the pdp-alignment stage), `zaddy` (the resource server with `enforce_policy { authorization_dpop; scope … }` on `/protected-dpop`), pep with `PEP_BACKEND=pdp`, `PEP_AS_ISSUER=http://zero-pdp:8011`, the client signing key, `PEP_API_UPSTREAM=http://zaddy:8010`, and Caddy fronting `/oauth2/*` + `/api/*` → pep. Document the run in `README.md`.

- [ ] **Step 2: Full verification**

Run:
```
go build ./pep/... && go vet ./pep/... && go test ./pep/...
go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|kv\|oauth\|pep/proxy\)'   # expect 0
```

- [ ] **Step 3: HITL (human)**

`docker compose -f pep/proxy/e2e/docker-compose.yaml up --build`, browse the front, log in via the PDP's mock IdP, then `GET /api/protected-dpop` → pep injects `Authorization: DPoP` + proof → **zaddy verifies the proof → 200**. A tampered/absent proof → rejected. Disconnect external network to confirm zero egress. Human confirms before the branch is finished.

- [ ] **Step 4: Commit**

```bash
git add pep/proxy/e2e/
git commit -m "test(pep): airgapped pdpBackend HITL — login via PDP, DPoP-bound /api call"
```

---

## Self-Review notes
- **Spec coverage (pdp-backend.md):** §2 architecture (Tasks 3–4, 6); §3 login flow port (Tasks 3–4); §4 per-session DPoP keys + signer seam (Tasks 1–2); §5 bindings/token-set — S4 ships one binding (Tasks 1, 7); §6 `/api` injection + allowlist (Task 6); §7 session model (Task 1); §8 config (Task 7); §11 airgapped HITL (Task 8); §12 BCP map — confidential client/PKCE/state/nonce/refresh/sender-constrained/allowlist all land in Tasks 3–7.
- **Deliberate read-then-port steps (not placeholders):** the `discoverMetadata`/`fetchNonce`/`exchange`/`introspectIdentity`/`refresh`/`resolveDecoupledAuthURL` bodies are direct ports of named `bff/bff.go` functions — each step names the source function + the one adaptation (session DPoP key, `b.http`). They are ports, not invented logic.
- **Type consistency:** `PDPConfig`, `asMetadata`, `pdpBackend`, `TokenEntry`, `sessionSigner`/`bffSigner`, `newSessionDPoPKey`/`parseSessionDPoPKey` names are consistent across Tasks 1–7. `Backend.DPoPKey()` is removed in Task 5 (no later task references it).
- **Cross-AS lazy acquisition + T3 browser-held keys are explicitly out of S4** (later stages, per the spec) — not in any task here.
