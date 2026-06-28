# pep gateway (S5) — multi-route reverse-proxy + injection

**Goal.** Give `pep/proxy` a flexible, multi-route reverse-proxy gateway so it can gate **and** proxy a set of
upstreams standalone (no Caddy in front), injecting either the user identity or a DPoP-bound access token per
route. This closes the one capability the `bff` has that pep lacks; with it, `bff` becomes redundant (see
[`BACKLOG.md`](BACKLOG.md)) and the `zero-bff-pdp` all-in-one is replaced by `zero-pdp` + `zero-pep-proxy`.

**Non-goals.** Cross-AS token acquisition (separate backlog item); replicating the bff's JSON SPA contract
(pep is server-rendered; the bff has no external consumers); changing the Caddy `forward_auth` path.

## Background — what already exists in pep

pep is **most** of the way there; S5 generalizes existing parts rather than building new ones:

- `headers.go` already produces the identity headers, including `X-Auth-Request-Identity` = base64url(JSON
  claims) plus the `X-Auth-Request-User/-Email/-Groups` set, with anti-spoofing (clears client-supplied
  copies). This **is** the InjectIdentity payload.
- `inject.go` already runs a **single** gated standalone reverse-proxy at `/api` with per-session DPoP
  injection (`mountAPI` / `apiProxy`, driven by `PEP_API_UPSTREAM` on the PDP backend). This **is** one
  InjectDPoP route.
- `proxy.go` has session retrieval (`currentSession`), the session store, and the `Backend` abstraction with
  `FreshAccessToken`.

The bff's engine to port is `bff/gateway/{gateway,host,inject}.go`: `Route{PathPrefix, UpstreamURL, Protected,
Inject, StripPrefix}`, longest-prefix match, `handleUnauthenticated` (HTML→302 / API→401), and
`RoutesFromEnv`.

## Architecture

A new `gateway` concern inside `pep/proxy` (kept small and focused): a `Gateway` `http.Handler` built from a
validated route table, mounted on the Server mux **after** `/oauth2/*` so the auth endpoints always win.

```
browser/API → pep mux
  ├── /oauth2/*            → existing handlers (auth, start, sign_in, callback, poll, userinfo, sign_out)
  └── (everything else)    → Gateway: longest-prefix match → gate → inject → reverse-proxy upstream
```

The Gateway is **active only when routes are configured**. With no routes pep is forward_auth-only, exactly as
today (behind Caddy). Both modes coexist: `handleAuth` (the Caddy `forward_auth` subrequest) is unchanged; the
Gateway is the standalone path.

### Route

```go
type Route struct {
    PathPrefix  string      // matched longest-first; "/api" beats "/"
    Upstream    string      // absolute URL (scheme+host required), validated at load
    Protected   bool        // default true; false = open passthrough
    Inject      InjectMode  // none | identity | dpop  (only meaningful when Protected)
    StripPrefix bool        // remove PathPrefix before proxying (/api/x → upstream /x)
}

type InjectMode string // "" (none) | "identity" | "dpop"
```

### Config — file + env shortcuts

Follows pep's established pattern (a `*_PATH` YAML for the rich case, env shortcuts for the common one; see
[`memory: env-var-path-suffix`]). Precedence: if `PEP_ROUTES_PATH` is set, the file is authoritative; else the
env shortcuts synthesize routes.

- `PEP_ROUTES_PATH` → `routes.yaml`: a list of routes.
  ```yaml
  routes:
    - path_prefix: /api
      upstream: http://resource-server:8080
      inject: dpop
      strip_prefix: true
    - path_prefix: /
      upstream: http://webapp:8080
      inject: identity
  ```
- Env shortcuts (no file): `PEP_API_UPSTREAM` → `{/api, dpop, strip_prefix}`; `PEP_WEBAPP_UPSTREAM` →
  `{/, identity}`. (`PEP_API_UPSTREAM` already exists and keeps working.)

Routes are sorted longest-`PathPrefix`-first at load. Duplicate prefixes are a load error.

### Inject modes

- **none** — gate only; forward nothing extra.
- **identity** — set the `X-Auth-Request-*` headers via `headers.go` (reused verbatim). Works with **any**
  backend (the identity lives on the session).
- **dpop** — attach `Authorization: DPoP <access_token>` plus a freshly minted proof bound to the upstream
  request (method + URL), using the **per-session** DPoP key. Reuses the existing `inject.go` minting path.
  Requires a token-bearing backend (PDP).

DPoP stays **per-session** (pep's model), not bff-level (one key per instance) — keeps sender-constraining
per user and works across replicas.

### Capability validation (load time)

A `dpop` route requires a backend whose `FreshAccessToken` yields a token — i.e. the **PDP backend**. A `dpop`
route configured with the provider backend (OIDC/OIDF/gemidp, identity-only) is a **configuration error at
startup**, not a runtime surprise. `identity`/`none` routes are valid with any backend.

### Request handling

1. Longest-prefix match; no match → 404.
2. Not protected → proxy through.
3. Protected → retrieve session; none → `handleUnauthenticated`.
4. `Inject != none` → `FreshAccessToken` (rotates/refreshes); on failure, delete session + expire cookie +
   `handleUnauthenticated`. Then inject per mode.
5. Reverse-proxy to the upstream (optionally stripping the prefix).

`handleUnauthenticated` (ported): `wantsHTML` (GET/HEAD + `Accept: text/html`) → `302 /oauth2/sign_in?rd=<orig
path>`, guarded against open redirects (local absolute path only); otherwise `401` JSON
`{"error":"unauthorized"}`.

### Backend seam

The Gateway is backend-agnostic for routing, gating, and identity injection (all Server-level). DPoP injection
is delegated to the token-bearing backend: the PDP backend exposes its existing per-session proof-minting as a
reusable injector the Gateway applies on `dpop` routes (generalizing today's hard-wired `apiProxy`). The
single `/api` proxy is removed and re-expressed as a route, so there is one proxy path, not two.

### Header hygiene

Every protected proxy clears client-supplied `X-Auth-Request-*` and `Authorization` before injecting (already
done for identity in `headers.go`; extend to the DPoP path). Hop-by-hop headers handled by `httputil.ReverseProxy`.

## Error handling

- Invalid upstream URL, duplicate prefix, or `dpop` route without a PDP backend → startup error (fail fast).
- Upstream unreachable → `httputil.ReverseProxy` default 502 (with an `ErrorHandler` logging the route).
- Token refresh failure mid-request → treat as unauthenticated (clear session, redirect/401).

## Testing

- **Unit** (`httptest`): longest-prefix selection; `identity` route sets `X-Auth-Request-Identity` that
  base64url-JSON-decodes to the claims and strips client copies; `dpop` route sets `Authorization: DPoP` +
  a verifiable proof bound to the upstream method/URL; unauthenticated HTML→302 (with guarded `rd`) vs API→401;
  `strip_prefix` rewrites the path; load errors (bad upstream, dup prefix, `dpop`+provider backend).
- **Module guard** unchanged: `go list -deps ./zaddy/cmd/zero-caddy | grep -c '…/\(oidf\|gemidp\|pep/proxy\)'`
  → 0.
- **HITL** (the bff-pdp replacement shape): pep standalone (no Caddy) with a `/` identity webapp route +
  an `/api` DPoP route, against the PDP backend + the airgapped mock-IdP harness. Prove: unauthenticated `/`
  → login UI; after login, `/` renders with injected identity; `/api` returns a zaddy-verified DPoP token;
  unauthenticated `/api` → 401.

## Ported vs changed (from `bff/gateway`)

| bff/gateway | pep/proxy gateway |
| --- | --- |
| `Route`, longest-prefix `match`, `ServeHTTP` gating | ported |
| `handleUnauthenticated`, `wantsHTML`, `isLocalPath` | ported (redirect target `/oauth2/sign_in`) |
| `RoutesFromEnv` (API/WEBAPP) | env shortcuts + **new** `PEP_ROUTES_PATH` YAML (flexible N routes) |
| bff-level DPoP key | **per-session** DPoP (pep's existing model) |
| identity header build | reuse pep `headers.go` (already present) |
| login UI at `/bff/` | pep server-rendered `/oauth2/sign_in` |

## Out of scope / follow-ups

- Cross-AS token acquisition (per-route different AS) — backlog item; here all `dpop` routes share the
  session's single AS binding.
- Removing `bff/` and repointing `zero-bff-pdp` — the next backlog step, unblocked once this lands + HITLs.
