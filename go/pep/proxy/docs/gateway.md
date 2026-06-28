# pep gateway (S5) — multi-route reverse-proxy + injection, on the pep enforcer model

**Goal.** Give `pep/proxy` a flexible, multi-route reverse-proxy gateway that gates **and** proxies a set of
upstreams standalone (no Caddy in front), injecting either the user identity or a DPoP-bound access token per
route. Gating reuses the **`pep.Enforcer`** policy model (the same one zaddy drives via `enforce_policy`), and
this stage implements the long-stubbed **`pep.EnforcerSessionCookie`**. Closing this gap makes `bff` redundant
([`BACKLOG.md`](BACKLOG.md)) and replaces the `zero-bff-pdp` all-in-one with `zero-pdp` + `zero-pep-proxy`.

**Non-goals.** Cross-AS token acquisition (backlog); replicating the bff's JSON SPA (pep is server-rendered, no
consumers); the full S6 zaddy in-process handler (this only *unblocks* it by making `EnforcerSessionCookie`
real).

## Background

- **pep enforcer model** (`pep/enforcers.go`): `Enforcer.Apply(ctx pep.Context, next pep.HandlerFunc)` — each
  policy calls `next(ctx)` (pass) or `ctx.Deny(err)` (stop). Combinators `EnforcerAllOf`/`EnforcerAnyOf`; leaf
  policies `EnforcerScope`, `EnforcerAuthorizationDPoP`/`Bearer`, and `EnforcerSessionCookie` (**a stub**:
  `"not implemented"`). `pep.Context` exposes `Writer/Request/Deny/WithDeny/UnmarshalClaims/Slogger`. zaddy
  wraps an enforcer tree as a Caddy handler (`enforce_policy`).
- **pep snapshot** (`pep/proxy/snapshot.go`): a **stateless** session cookie as a JWE (`dir`+`A256GCM`, one
  key) carrying only the **identity** (the DPoP private key never leaves the server). `mint(sid, identity)` /
  `open(token)`.
- **pep identity headers** (`headers.go`): `X-Auth-Request-*` incl. `X-Auth-Request-Identity` =
  base64url(JSON), with anti-spoofing. The per-session DPoP minting lives in `inject.go`/`signer.go`.

## Two enforcers, one model

The DPoP key constraint forces two session gates that share the `pep.Enforcer` model:

| Gate | Where | State | Yields | Used by |
| --- | --- | --- | --- | --- |
| `EnforcerSessionCookie` | `pep` (this stage implements it) | **stateless** (snapshot JWE) | identity | zaddy `forward_auth`; gateway identity routes (default) |
| stateful session gate | `pep/proxy` | **stateful** (kv lookup) | full session (identity **+** DPoP key/token) | gateway `dpop` routes, **opt-in** |

The stateful gate is **only used when explicitly configured** (`gate: session`) — the stateless snapshot is
the default, so most requests never touch the kv. `inject: dpop` requires `gate: session` (the snapshot can't
carry the DPoP key); this is enforced at load.

### `pep.EnforcerSessionCookie` (stateless, implemented here)

Move the snapshot open (JWE `dir`+`A256GCM`) into `pep` so the enforcer — and thus zaddy — can validate the
cookie without kv. Align the stub's fields to the real format: `CookieName` + `KeyPath` (one key;
drop the stub's separate `DecryptKeyPath`/`VerifyKeyPath` — GCM authenticates, so there is no second key).
`Apply`: read the cookie → `open` → on success stash the identity on the context and `next`; else `Deny`.
`pep/proxy`'s `snapshotter` is refactored to call the shared open (DRY); minting stays in `pep/proxy`.

### Stateful gate (gateway, opt-in)

A `pep.Enforcer` implemented in `pep/proxy` that resolves the cookie to a full `Session` via the existing
`currentSession`/kv path, stashes it on the context, and `next`. This is the only gate that exposes the DPoP
key + access token to the inject step.

## Gateway request flow

A `Gateway` `http.Handler` mounted on the Server mux **after** `/oauth2/*` (auth endpoints always win), active
only when routes are configured (else pep is forward_auth-only, unchanged).

```
match longest prefix → route.Policy.Apply(gctx, next) ─pass→ inject(identity|dpop) → reverse-proxy upstream
                                                       └deny→ HTML: 302 /oauth2/sign_in?rd=… · API: 401 JSON
```

`route.Policy` is a `pep.Enforcer` tree (the gate, optionally `AllOf` with `EnforcerScope`). The terminal
`next` is the inject+proxy. `gctx` is a gateway `pep.Context` whose `UnmarshalClaims` sources the session
identity (snapshot or full session), so `EnforcerScope` works unchanged. `Deny` routes to the HTML/API branch.

## Route config — file + env shortcuts

Sugar over the enforcer tree (a raw enforcer tree in YAML would be unusable). Loader builds the `pep.Enforcer`
from `gate` + `scope`.

```yaml
routes:
  - path_prefix: /api
    upstream: http://resource-server:8080
    inject: dpop          # ⇒ gate: session (stateful) required
    gate: session
    strip_prefix: true
  - path_prefix: /admin
    upstream: http://app:8080
    inject: identity
    gate: snapshot        # default; stateless
    scope: admin          # ⇒ AllOf(SessionCookie, Scope{admin})
  - path_prefix: /
    upstream: http://app:8080
    inject: identity        # gate defaults to snapshot
```

- `gate`: `none` (passthrough) | `snapshot` (stateless, default for protected) | `session` (stateful kv).
- `scope`: optional; wraps the gate in `AllOf(gate, EnforcerScope{scope})`.
- Env shortcuts: `PEP_API_UPSTREAM` → `{/api, dpop, gate:session, strip}`; `PEP_WEBAPP_UPSTREAM` →
  `{/, identity, gate:snapshot}`. `PEP_ROUTES_PATH` (YAML) is authoritative when set.

Validation (load time): longest-prefix sort; duplicate prefix / bad upstream / bad enum → error;
`inject: dpop` with `gate != session` → error; `inject: dpop` with a non-PDP backend → error
(`requireDPoPCapability`).

## Inject (terminal next)

- **identity** — `setIdentityHeaders(out.Header, identity)` from the context (reuses `headers.go`); strips
  client `X-Auth-Request-*`.
- **dpop** — needs the full session (so `gate: session`): `FreshAccessToken` + per-session proof minting
  (delegated to the PDP backend via `dpopForwarder`), replacing client `Authorization`.
- **none** — gate only.

## Error handling

- Bad upstream / dup prefix / `dpop`+`gate!=session` / `dpop`+non-PDP backend → startup error.
- `Deny` → HTML (`GET`/`HEAD` + `Accept: text/html`) 302 to `/oauth2/sign_in?rd=…` (open-redirect-guarded),
  else 401 JSON.
- Upstream unreachable → 502 JSON via the proxy `ErrorHandler`.

## Testing

- **pep**: `EnforcerSessionCookie` opens a valid snapshot → `next` with identity; tampered/expired → `Deny`.
- **pep/proxy unit**: longest-prefix match; identity inject (header decodes, client copies stripped, strip);
  dpop inject (Authorization DPoP + proof bound to the outbound request); `EnforcerScope` over the gateway
  context allows/denies; load errors (`dpop`+`gate:snapshot`, `dpop`+provider backend, dup prefix).
- **Module guard**: `go list -deps ./zaddy/cmd/zero-caddy | grep -c '…/\(oidf\|gemidp\|pep/proxy\)'` → 0
  (zaddy gains `EnforcerSessionCookie` from `pep`, never `pep/proxy`).
- **HITL** (bff-pdp replacement shape): pep standalone (no Caddy), a `/` identity route (gate snapshot) + an
  `/api` dpop route (gate session), PDP backend + mock-IdP harness. Unauthenticated `/` (browser) → login;
  after login `/` renders with injected identity; `/api` → zaddy-verified DPoP; unauthenticated `/api` → 401.

## Reused vs new

| Piece | Status |
| --- | --- |
| `pep.Enforcer`/`EnforcerScope`/`AllOf`/`AnyOf` | reused |
| `pep.EnforcerSessionCookie` | **implemented** (stateless snapshot, fields aligned) |
| snapshot open | **moved to `pep`**; `pep/proxy` snapshotter delegates |
| reverse-proxy / strip / header hygiene / longest-prefix match | from S5 Tasks 1-3 |
| identity headers (`headers.go`), per-session DPoP (`inject.go`/`signer.go`) | reused |
| `Route.Protected bool` | **replaced** by `Route` gate/scope → `Policy pep.Enforcer` |
| stateful gateway gate, gateway `pep.Context` | **new** in `pep/proxy` |

## Out of scope / follow-ups

- S6: zaddy in-process handler + `enforce_policy session_cookie` end to end — unblocked by this stage.
- Cross-AS token acquisition; raw enforcer-tree config (only `gate`/`scope` sugar now).
