# PDP → pep Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `zero-pdp` up to the pep house standard (providers via the shared `openid-providers.yaml`, `*_PATH` secrets, the `/app`+`/etc/pdp` Docker shape, `CONFIG.md`/`DOCKERHUB.md`), bake in a `NonProdMode` mock IdP, and put the PDP in `docker compose` — so the pep **S4** HITL is fully airgapped.

**Architecture:** The PDP keeps its rich domain config (`pdp.yaml`: issuer, clients, products, policies, endpoints) but **sources its IdPs from a flat `openid-providers.yaml`** (`PDP_OPENID_PROVIDERS_PATH`, default `openid-providers.yaml`), reusing the *same leaf types* pep uses. A `NonProdMode` mock IdP short-circuits `startOpenidProviderLogin` to auto-complete the auth-code flow with a canned identity (no real OP). The compose runs the PDP itself with `PDP_NON_PROD=true` — zero network egress.

**Tech Stack:** Go (stdlib `net/http`, cobra/viper, `gopkg.in/yaml.v2`), `github.com/lestrrat-go/jwx/v3`, `segmentio/ksuid`, docker compose, `just`.

## Global Constraints

- Module path: `github.com/gematik/zero-lab/go`. Provider leaf types reused verbatim: `oauth/oidc.Config`, `gemidp.ClientConfig`, `oidf.RelyingPartyConfig`.
- Secrets come from **`*_PATH` files only** — never env values, never stored in `kv`.
- `openid-providers.yaml` schema is **flat**: top-level `oidc:` / `gemidp:` / `oidf:` (identical to pep's `openidProviders` struct).
- PDP config file: `pdp.yaml` via `--config-file`/`-f` / `PDP_CONFIG_FILE` (default `pdp.yaml`); workdir via `--workdir`/`-w` / `PDP_WORKDIR`. The PDP uses `gopkg.in/yaml.v2` (not v3).
- Tests: table-driven, `httptest`, in-memory store via `kv.NewMemory()`; call handler methods directly.
- The mock IdP is **only** reachable when `NonProdMode` is true; it must be impossible to enable under a prod config.
- Module graph unchanged: `go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|kv\|oauth\|pep/proxy\)'` stays `0`.
- Commits: conventional style, no AI attribution. Branch: `feat/pdp-pep-alignment`.

## File Structure

- **Create** `pdp/openid_providers.go` — the flat `openid-providers.yaml` loader (mirrors pep's `openidProviders`); returns the three provider slices/pointer.
- **Create** `pdp/openid_providers_test.go` — loader tests.
- **Modify** `pdp/pdp.go` — `LoadConfigFile` also loads `openid-providers.yaml` and populates `AuthzServerConfig` providers; resolve the path relative to the config dir.
- **Modify** `pdp/pdp_test.go` (create if absent) — `LoadConfigFile` integration test.
- **Modify** `pdp/authzserver/config.go` — add a `MockIDP *MockIDPConfig` field (non-prod canned identity).
- **Create** `pdp/authzserver/mock_idp.go` — `MockIDPConfig` + `completeMockLogin` helper.
- **Create** `pdp/authzserver/mock_idp_test.go` — the airgapped auth-code-flow test.
- **Modify** `pdp/authzserver/server.go` — carry `mockIDP` on the `Server`.
- **Modify** `pdp/authzserver/authorize.go` — `nonProdMode` short-circuit in `startOpenidProviderLogin`.
- **Modify** `pdp/cmd/zero-pdp/Dockerfile` — `/app` binary + `WORKDIR /etc/pdp` (drop the `PDP_WORKDIR` dance).
- **Modify** `pdp/docker-compose.yaml` — add the `zero-pdp` service (airgapped, `PDP_NON_PROD=true`).
- **Create** `pdp/cmd/zero-pdp/CONFIG.md`, `pdp/cmd/zero-pdp/DOCKERHUB.md`, `pdp/cmd/zero-pdp/openid-providers.example.yaml`.

---

### Task 1: Shared `openid-providers.yaml` loader for the PDP

**Files:**
- Create: `pdp/openid_providers.go`
- Test: `pdp/openid_providers_test.go`
- Modify: `pdp/pdp.go` (`LoadConfigFile`)

**Interfaces:**
- Produces: `func LoadOpenidProviders(path string) (oidcs []oidc.Config, gemidps []gemidp.ClientConfig, rp *oidf.RelyingPartyConfig, err error)` and the package-level default `const defaultOpenidProvidersFile = "openid-providers.yaml"`.
- Consumes (in `pdp.go`): assigns into `cfg.AuthzServerConfig.OidcProviders`, `.GematikIdp`, `.OidfRelyingPartyConfig`.

- [ ] **Step 1: Write the failing test**

Create `pdp/openid_providers_test.go`:

```go
package pdp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOpenidProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openid-providers.yaml")
	yaml := `
oidc:
  - issuer: https://op.example.com
    client_id: cid
    name: Example
gemidp:
  - client_id: gid
    environment: ref
oidf:
  sub: https://rp.example.com
  fed_master_url: https://app-test.federationmaster.de
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	oidcs, gemidps, rp, err := LoadOpenidProviders(path)
	if err != nil {
		t.Fatalf("LoadOpenidProviders: %v", err)
	}
	if len(oidcs) != 1 || oidcs[0].Issuer != "https://op.example.com" {
		t.Errorf("oidc = %+v", oidcs)
	}
	if len(gemidps) != 1 || gemidps[0].ClientID != "gid" {
		t.Errorf("gemidp = %+v", gemidps)
	}
	if rp == nil || rp.Subject != "https://rp.example.com" {
		t.Errorf("oidf = %+v", rp)
	}
}

func TestLoadOpenidProvidersMissingFile(t *testing.T) {
	if _, _, _, err := LoadOpenidProviders(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
```

> Note: confirm the `oidf.RelyingPartyConfig` field for the subject — the spec/grep show `Subject` (yaml `sub`). If the field is named differently, match it; do not invent.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pdp/ -run TestLoadOpenidProviders -v`
Expected: FAIL — `undefined: LoadOpenidProviders`.

- [ ] **Step 3: Write the loader**

Create `pdp/openid_providers.go`:

```go
package pdp

import (
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"gopkg.in/yaml.v2"
)

const defaultOpenidProvidersFile = "openid-providers.yaml"

// openidProviders is the flat openid-providers.yaml schema — the same shape pep loads, reusing each
// provider's package config type. The PDP and pep share the file format without a shared package.
type openidProviders struct {
	OIDC   []oidc.Config            `yaml:"oidc"`
	Gemidp []gemidp.ClientConfig    `yaml:"gemidp"`
	OIDF   *oidf.RelyingPartyConfig `yaml:"oidf"`
}

// LoadOpenidProviders reads the flat openid-providers.yaml. ${VAR} placeholders expand from the
// environment. Relative paths inside the OIDF config resolve against the file's directory (set by the caller
// via OidfRelyingPartyConfig.BaseDir).
func LoadOpenidProviders(path string) ([]oidc.Config, []gemidp.ClientConfig, *oidf.RelyingPartyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read providers %q: %w", path, err)
	}
	var op openidProviders
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &op); err != nil {
		return nil, nil, nil, fmt.Errorf("parse providers %q: %w", path, err)
	}
	return op.OIDC, op.Gemidp, op.OIDF, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pdp/ -run TestLoadOpenidProviders -v`
Expected: PASS (both cases).

- [ ] **Step 5: Wire it into `LoadConfigFile`**

In `pdp/pdp.go`, after `cfg.AuthzServerConfig.BaseDir = cfg.BaseDir` (currently line ~37) and before `return cfg, nil`, insert:

```go
	// Providers come from a shared openid-providers.yaml (same format pep uses). Path from
	// PDP_OPENID_PROVIDERS_PATH, else openid-providers.yaml next to the config file. When present it is the
	// source of OIDC/gemidp/OIDF providers; absent, any inline providers in pdp.yaml are kept (back-compat).
	providersPath := os.Getenv("PDP_OPENID_PROVIDERS_PATH")
	if providersPath == "" {
		providersPath = filepath.Join(cfg.BaseDir, defaultOpenidProvidersFile)
	}
	if _, statErr := os.Stat(providersPath); statErr == nil {
		oidcs, gemidps, rp, err := LoadOpenidProviders(providersPath)
		if err != nil {
			return nil, err
		}
		cfg.AuthzServerConfig.OidcProviders = oidcs
		cfg.AuthzServerConfig.GematikIdp = gemidps
		if rp != nil {
			rp.BaseDir = filepath.Dir(providersPath)
			cfg.AuthzServerConfig.OidfRelyingPartyConfig = rp
		}
	} else if os.Getenv("PDP_OPENID_PROVIDERS_PATH") != "" {
		return nil, fmt.Errorf("PDP_OPENID_PROVIDERS_PATH %q: %w", providersPath, statErr)
	}
```

`os` and `path/filepath` are already imported in `pdp.go`.

- [ ] **Step 6: Integration test for `LoadConfigFile`**

Create/extend `pdp/pdp_test.go`:

```go
package pdp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFileMergesProviders(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "openid-providers.yaml"), []byte(
		"oidc:\n  - issuer: https://op.example.com\n    client_id: cid\n"), 0o600)
	cfgPath := filepath.Join(dir, "pdp.yaml")
	os.WriteFile(cfgPath, []byte("authorization_server:\n  issuer: https://as.example.com\n"), 0o600)

	cfg, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if len(cfg.AuthzServerConfig.OidcProviders) != 1 ||
		cfg.AuthzServerConfig.OidcProviders[0].Issuer != "https://op.example.com" {
		t.Errorf("providers not merged: %+v", cfg.AuthzServerConfig.OidcProviders)
	}
}
```

Run: `go test ./pdp/ -run TestLoadConfigFile -v` — Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pdp/openid_providers.go pdp/openid_providers_test.go pdp/pdp.go pdp/pdp_test.go
git commit -m "feat(pdp): load IdPs from the shared openid-providers.yaml"
```

---

### Task 2: NonProdMode mock IdP

**Files:**
- Create: `pdp/authzserver/mock_idp.go`, `pdp/authzserver/mock_idp_test.go`
- Modify: `pdp/authzserver/config.go`, `pdp/authzserver/server.go`, `pdp/authzserver/authorize.go`

**Interfaces:**
- Produces: `type MockIDPConfig struct { Subject string; Claims map[string]any }`; `func (s *Server) completeMockLogin(w http.ResponseWriter, r *http.Request, session *AuthzServerSession) error`.
- Consumes: `s.nonProdMode bool`, `s.sessionStore.SaveAutzhServerSession`, `generateNonce`, `AuthzServerSession.{Code,RedirectURI,State}`.

- [ ] **Step 1: Add the config field**

In `pdp/authzserver/config.go`, add to `Config`:

```go
	// MockIDP, when set and NonProdMode is on, makes the authorization endpoint auto-complete login with this
	// canned identity instead of redirecting to a real OP. Non-prod test harness only.
	MockIDP *MockIDPConfig `yaml:"mock_idp" validate:"omitempty"`
```

- [ ] **Step 2: Write the failing test**

Create `pdp/authzserver/mock_idp_test.go` (follow `server_test.go`'s `newTestServer` helper style; add a `non_prod`/`MockIDP` variant):

```go
package authzserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMockIDPCompletesAuthCodeFlow(t *testing.T) {
	server, _ := newTestServer(t) // from server_test.go
	server.nonProdMode = true
	server.mockIDP = &MockIDPConfig{Subject: "X110000001", Claims: map[string]any{"name": "Test User"}}

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"https://rp.example.com/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"st-123"},
		"scope":                 {"test-scope"},
	}
	req := httptest.NewRequest(http.MethodGet, "/auth?"+form.Encode(), nil)
	rec := httptest.NewRecorder()
	if err := server.AuthorizationEndpoint(rec, req); err != nil {
		t.Fatalf("AuthorizationEndpoint: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.example.com/callback?") {
		t.Fatalf("redirected to %q, want the client callback (no real OP)", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" || u.Query().Get("state") != "st-123" {
		t.Errorf("missing code or wrong state: %q", loc)
	}
}
```

> Adjust `newTestServer`'s product/client to allow `test-scope` + the `https://rp.example.com/callback` redirect (they already are, per `server_test.go`). The `test-product` must resolve for `test-client`.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./pdp/authzserver/ -run TestMockIDPCompletesAuthCodeFlow -v`
Expected: FAIL — `server.mockIDP` undefined / redirect goes to a real OP (or `GetOpenidClient` error).

- [ ] **Step 4: Carry `mockIDP` on the Server**

In `pdp/authzserver/server.go`: add `mockIDP *MockIDPConfig` to the `Server` struct, and in `New(cfg)` set `mockIDP: cfg.MockIDP` (next to the existing `nonProdMode: cfg.NonProdMode`).

- [ ] **Step 5: Write the mock-login helper**

Create `pdp/authzserver/mock_idp.go`:

```go
package authzserver

import (
	"net/http"
	"net/url"
)

// MockIDPConfig is a canned identity used in NonProdMode to complete login without a real OpenID Provider.
type MockIDPConfig struct {
	Subject string         `yaml:"subject"`
	Claims  map[string]any `yaml:"claims"`
}

// completeMockLogin finishes the authorization-code flow with the canned identity: it stashes the claims on
// the session, mints an authorization code, and redirects back to the client — the same tail as
// OPCallbackEndpoint, but with no upstream OP. NonProdMode only.
func (s *Server) completeMockLogin(w http.ResponseWriter, r *http.Request, session *AuthzServerSession) error {
	session.MockClaims = s.mockIDP.Claims
	session.Code = generateNonce(64)
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: "unable to save mock session: " + err.Error(),
		})
	}
	params := url.Values{}
	params.Set("code", session.Code)
	params.Set("state", session.State)
	http.Redirect(w, r, session.RedirectURI+"?"+params.Encode(), http.StatusFound)
	return nil
}
```

Add `MockClaims map[string]any \`json:"mock_claims,omitempty"\`` to `AuthzServerSession` in `pdp/authzserver/server_session.go` (so introspection can read the canned identity — wired in Step 7).

- [ ] **Step 6: Hook the short-circuit into `startOpenidProviderLogin`**

In `pdp/authzserver/authorize.go`, at the top of `startOpenidProviderLogin` (before `s.GetOpenidClient`):

```go
	if s.nonProdMode && s.mockIDP != nil {
		return s.completeMockLogin(w, r, session)
	}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./pdp/authzserver/ -run TestMockIDPCompletesAuthCodeFlow -v`
Expected: PASS.

- [ ] **Step 8: Surface the canned identity at introspection**

Read `pdp/authzserver/introspect.go`. Where it builds the introspection response for an active token, add the session's `MockClaims` to the returned identity (matching how it returns identity for a real session — keep the same field/shape). Add a test asserting introspection of a mock-issued token returns `name: Test User`. (If introspection does not yet surface identity at all, leave a one-line `// identity passthrough lands with pep S4 introspection wiring` and assert only token activeness — do **not** invent an identity schema.)

Run: `go test ./pdp/authzserver/ -v` — Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pdp/authzserver/mock_idp.go pdp/authzserver/mock_idp_test.go pdp/authzserver/config.go pdp/authzserver/server.go pdp/authzserver/server_session.go pdp/authzserver/authorize.go pdp/authzserver/introspect.go
git commit -m "feat(pdp): NonProdMode mock IdP — airgapped auth-code login"
```

---

### Task 3: Align the Dockerfile to the pep pattern

**Files:**
- Modify: `pdp/cmd/zero-pdp/Dockerfile`

- [ ] **Step 1: Rewrite the runtime stage**

Replace `pdp/cmd/zero-pdp/Dockerfile` with (binary in `/app`, config mount at `/etc/pdp` as WORKDIR, no `PDP_WORKDIR` dance):

```dockerfile
FROM golang:1.26 AS build
ARG VERSION=dev
WORKDIR /src
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/pdp.Version=${VERSION}" \
	-o /out/zero-pdp ./pdp/cmd/zero-pdp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Binary in /app, config + secrets mounted at the WORKDIR /etc/pdp without shadowing the executable.
COPY --from=build /out/zero-pdp /app/zero-pdp
WORKDIR /etc/pdp
ENV PRETTY_LOGS=false
ENTRYPOINT ["/app/zero-pdp"]
```

The PDP's `--config-file` defaults to `pdp.yaml`, resolved from the WORKDIR (`/etc/pdp`); `openid-providers.yaml` sits beside it.

- [ ] **Step 2: Build it**

Run: `just docker-build-pdp 2>&1 | tail -3`
Expected: `naming to docker.io/<user>/zero-pdp:<modver>` (no error).

- [ ] **Step 3: Commit**

```bash
git add pdp/cmd/zero-pdp/Dockerfile
git commit -m "build(pdp): align Dockerfile to the pep /app + /etc/pdp pattern"
```

---

### Task 4: Airgapped compose (PDP + mock IdP in a container)

**Files:**
- Modify: `pdp/docker-compose.yaml`
- Create: `pdp/cmd/zero-pdp/openid-providers.example.yaml`

- [ ] **Step 1: Add the PDP service**

Append a `zero-pdp` service to `pdp/docker-compose.yaml` (keep the existing `postgres` service + `volumes`):

```yaml
  zero-pdp:
    build:
      context: ../.. # the go/ workspace root (for go.work)
      dockerfile: pdp/cmd/zero-pdp/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      PRETTY_LOGS: "false"
      PDP_NON_PROD: "true"
      DATABASE_URL: "postgres://zero:zero@postgres:5432/zero?sslmode=disable"
    volumes:
      - ./config:/etc/pdp:ro   # pdp.yaml (with mock_idp + non_prod_mode) + openid-providers.yaml + sign.jwk
    ports:
      - "8011:8011"
    command: ["start"]
```

> `PDP_NON_PROD` is read where `start` builds the config — if the PDP doesn't yet map that env to `NonProdMode`, wire it in `pdp/cmd/zero-pdp/cmd/` (viper `BindEnv`/`AutomaticEnv` with prefix `PDP_`) so `PDP_NON_PROD=true` sets `non_prod_mode`. Confirm by reading `root.go`; add the binding if missing.

- [ ] **Step 2: Provide the example providers file + a minimal non-prod config**

Create `pdp/cmd/zero-pdp/openid-providers.example.yaml`:

```yaml
# Providers the PDP authenticates users against. Shared flat format with pep (oidc / gemidp / oidf).
# In NonProdMode with mock_idp set (see pdp.yaml), the PDP skips these and auto-issues a canned identity.
oidc:
  - issuer: https://op.example.com
    client_id: "<client-id>"
    client_secret: "<secret>"
    name: Example OP
```

- [ ] **Step 3: Verify compose parses**

Run: `docker compose -f pdp/docker-compose.yaml config >/dev/null && echo OK`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add pdp/docker-compose.yaml pdp/cmd/zero-pdp/openid-providers.example.yaml
git commit -m "build(pdp): run the PDP (NonProd mock IdP) in compose, airgapped"
```

---

### Task 5: `CONFIG.md` + `DOCKERHUB.md`

**Files:**
- Create: `pdp/cmd/zero-pdp/CONFIG.md`, `pdp/cmd/zero-pdp/DOCKERHUB.md`

- [ ] **Step 1: Write `CONFIG.md`**

Create `pdp/cmd/zero-pdp/CONFIG.md` mirroring pep's split (providers file vs domain YAML vs env), tables not prose:

```markdown
# zero-pdp — configuration

Three sources:
- `openid-providers.yaml` — the IdPs the PDP authenticates against (shared flat format with pep:
  `oidc` / `gemidp` / `oidf`). Loaded from `PDP_OPENID_PROVIDERS_PATH` (default `openid-providers.yaml`).
- `pdp.yaml` — the PDP domain config (issuer, scopes, clients, products, policies, endpoints, `non_prod_mode`,
  `mock_idp`). Selected with `-f` / `PDP_CONFIG_FILE` (default `pdp.yaml`).
- Environment — runtime + secrets via `*_PATH` files.

| Var | Purpose | Default |
| --- | --- | --- |
| `PDP_CONFIG_FILE` (`-f`) | the domain config file | `pdp.yaml` |
| `PDP_OPENID_PROVIDERS_PATH` | the providers file | `openid-providers.yaml` |
| `PDP_WORKDIR` (`-w`) | chdir before loading config | — |
| `PDP_NON_PROD` | `true` → NonProdMode (enables the mock IdP) | `false` |
| `DATABASE_URL` | Postgres kv store; unset → in-memory | in-memory |

Secrets (`sign_jwk_path`, `clients_policy_path`, …) are files referenced by path — never env values, never in
the kv store. `mock_idp` (a canned identity) is honored **only** in NonProdMode.
```

- [ ] **Step 2: Write `DOCKERHUB.md`**

Create `pdp/cmd/zero-pdp/DOCKERHUB.md` (overview + run + config table + tags), same shape as the pep one — `scratch` image, binary `/app/zero-pdp`, config mounted at `/etc/pdp`, link back to `CONFIG.md` on GitHub.

- [ ] **Step 3: Commit**

```bash
git add pdp/cmd/zero-pdp/CONFIG.md pdp/cmd/zero-pdp/DOCKERHUB.md
git commit -m "docs(pdp): CONFIG.md + DOCKERHUB.md (pep-aligned)"
```

---

### Task 6: Full-suite + module-graph verification

- [ ] **Step 1: Build + vet + test**

Run: `go build ./pdp/... && go vet ./pdp/... && go test ./pdp/...`
Expected: builds clean; `ok` for `./pdp/` and `./pdp/authzserver/`.

- [ ] **Step 2: Module-graph guard**

Run: `go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|kv\|oauth\|pep/proxy\)'`
Expected: `0`.

- [ ] **Step 3: HITL (human) — airgapped token via the mock IdP**

With `config/pdp.yaml` (`non_prod_mode: true`, a `mock_idp`, a `test-client`/`test-product`) + `config/openid-providers.yaml` + `config/sign.jwk`:

```bash
docker compose -f pdp/docker-compose.yaml up --build
```

Drive an authorization-code request (browser or `curl`) for `test-client` → confirm a redirect to the client `redirect_uri` carrying `code`+`state` **with no external network**, then exchange the code at `/token` for an access token. This is the airgapped path pep S4's HITL composes with. (Disconnect the network to prove zero egress.)

- [ ] **Step 4: Commit any fixes; open the PR when green.**

---

## Self-Review notes
- **Spec coverage:** providers→`openid-providers.yaml` (T1), env+`*_PATH` (T1/T5), `/app`+`/etc/pdp` Docker (T3), `just` targets + version stamp (pre-existing — verified in T3/T6), `CONFIG.md`/`DOCKERHUB.md` (T5), secure defaults — NonProd off by default, mock gated (T2), mock IdP (T2), PDP in compose (T4). All mapped.
- **Open verbatim gaps deliberately flagged (read-then-wire, not placeholders):** the env→`NonProdMode` viper binding (T4 S1) and the introspection identity passthrough (T2 S8) depend on files to be read at implementation time; each step says exactly what to read and what to add, and forbids inventing schemas.
- **Type consistency:** `LoadOpenidProviders` signature is identical across T1; `MockIDPConfig`/`mockIDP`/`MockClaims`/`completeMockLogin` names are consistent across T2; `AuthzServerSession`/`SaveAutzhServerSession` match the existing code (note the existing typo in the method name — keep it).
