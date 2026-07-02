# pep gateway (S5) — Implementation Plan (enforcer-based)

> REQUIRED SUB-SKILL: superpowers:executing-plans. TDD, bite-sized, frequent commits. Steps use `- [ ]`.

**Goal:** A multi-route reverse-proxy gateway in `pep/proxy` whose gating reuses the `pep.Enforcer` model and
implements the stubbed `pep.EnforcerSessionCookie`; per route it injects identity or a DPoP-bound token.

**Architecture:** Reverse-proxy engine (Tasks 1-3 already built: config, match, proxy/strip/hygiene, identity
inject) + a reworked gating layer. Session resolution is per-route: `gate: snapshot` (stateless JWE, shared
with the new `pep.EnforcerSessionCookie`) or `gate: session` (stateful kv, required for `dpop`). Policy checks
(`scope`) run as `pep.Enforcer`s over a `pep.Context` whose claims are the session identity. See
[`gateway.md`](gateway.md).

## Global Constraints

- Branch `feat/pep-gateway`. Ask before commit. Never push.
- `/oauth2/*` mounted first; gateway active only when routes configured (else forward_auth-only, unchanged).
- `inject: dpop` ⇒ `gate: session` ⇒ PDP backend; all checked at load.
- DPoP key is per-session and **never** enters the cookie — `dpop` requires the stateful gate.
- Module guard: `go list -deps ./zaddy/cmd/zero-caddy | grep -c '…/\(oidf\|gemidp\|pep/proxy\)'` → 0. zaddy may
  pull `pep` (for `EnforcerSessionCookie`), never `pep/proxy`.
- Go-idiomatic initialisms; no narration comments.

## Status of the already-built tasks (commit d065f12)

- **Done & kept:** route config loading + validation (`gateway_config.go`), longest-prefix match, the
  reverse-proxy with strip + header hygiene, identity injection (`gateway.go`), `dpopForwarder` seam
  (`backend.go`). Tests green.
- **Reworked below:** `Route.Protected bool` → `gate`/`scope`; the gating layer moves to the enforcer model.

---

### Task R1: Route gate/scope config (rework of Task 1)

**Files:** `pep/proxy/gateway_config.go`, `pep/proxy/gateway_test.go`

- Replace `Route.Protected bool` with `Gate string` (`"" | none | snapshot | session`) + `Scope string`.
  `routesFromEnv`: `PEP_API_UPSTREAM` → `{/api, inject:dpop, gate:session, strip}`; `PEP_WEBAPP_UPSTREAM` →
  `{/, inject:identity, gate:snapshot}`. Default gate for a protected route (any `inject`) is `snapshot`.
- `validateRoutes` adds: `gate` enum check; `inject:dpop ⇒ gate:session` else error; longest-prefix sort,
  dup-prefix + bad-upstream as before.
- [ ] Tests: env shortcuts produce the gates; `inject:dpop`+`gate:snapshot` → error; `gate` enum guarded.
- [ ] Commit: `feat(pep): gateway route gate/scope config`.

### Task R2: Shared snapshot-open + `pep.EnforcerSessionCookie`

**Files:** `pep/session_cookie.go` (new), `pep/enforcers.go` (replace the stub), `pep/proxy/snapshot.go`
(delegate), tests in `pep/`.

- Move the JWE open (`dir`+`A256GCM`, one key; parse `{sid, identity, exp}`; expiry check) into `pep` as
  `OpenSessionCookie(token string, keys [][]byte) (identity map[string]any, sid string, ok bool)`.
- Rewrite `EnforcerSessionCookie` fields to `CookieName` + `KeyPath` (+ optional `PreviousKeyPath`); `Apply`:
  read cookie → `OpenSessionCookie` → on ok set `pepContext.claimsRaw = json(identity)` and `next`; else
  `ctx.Deny`. (Add a package-internal `setClaims([]byte)` on `pepContext`.)
- `pep/proxy/snapshot.go` `open` calls `pep.OpenSessionCookie` (DRY); `mint` stays.
- [ ] Tests (pep): valid snapshot → `next` runs with identity in claims; tampered/expired → `Deny`.
- [ ] Guard stays 0. Commit: `feat(pep): implement EnforcerSessionCookie (stateless snapshot)`.

### Task R3: Gateway session resolution + `pep.Context`

**Files:** `pep/proxy/gateway.go`, `pep/proxy/gateway_session.go` (new), tests.

- `resolveGatewaySession(r, gate) (*Session, map[string]any, bool)`: `snapshot` → read cookie +
  `pep.OpenSessionCookie` (identity only, `*Session` nil); `session` → `currentSession` (full session +
  `sess.Identity`).
- Build a gateway `pep.Context` (or reuse `pep.NewContext` + `setClaims`) carrying the identity for
  `EnforcerScope`.
- [ ] Tests: snapshot path yields identity, no session; session path yields full session.
- [ ] Commit: `feat(pep): gateway per-route session resolution (snapshot/stateful)`.

### Task R4: Reworked engine — gate, policy (scope), inject, unauth branch

**Files:** `pep/proxy/gateway.go`, tests.

- `ServeHTTP`: match → `gate==none` proxy → else `resolveGatewaySession`; fail → `handleUnauthenticated`
  (HTML 302 `/oauth2/sign_in?rd=…` / API 401, already built). If `Scope != ""`, run
  `(&pep.EnforcerScope{Scope: rt.Scope}).Apply(ctx, next)` with `Deny` → `handleUnauthenticated`/403; else
  call next directly. `next` = inject + proxy.
- Identity inject reuses the built Rewrite (identity from the resolved identity map); DPoP in R5.
- [ ] Tests: scope allow/deny over the gateway context; identity route end to end; unauth branch.
- [ ] Commit: `feat(pep): enforcer-based gateway gating (session_cookie + scope)`.

### Task R5: DPoP inject on the stateful path

**Files:** `pep/proxy/backend_pdp.go` (add `injectDPoP`, delete `inject.go`), `pep/proxy/gateway.go`, tests.

- Add `(*pdpBackend) injectDPoP(out, sess, token)` (refactor the `apiProxy` minting: `parseSessionDPoPKey` +
  `signer.dpopProof` + set `Authorization: DPoP` + `dpop.DPoPHeaderName`). Delete `inject.go`.
- Gateway dpop route (gate:session): `FreshAccessToken` + `g.injectDPoP` (via `dpopForwarder`) in the Rewrite.
- [ ] Tests: dpop route sets `Authorization: DPoP` + proof bound to the outbound request.
- [ ] Commit: `feat(pep): gateway DPoP injection; subsume the single /api proxy`.

### Task R6: Wire into the Server; drop the old apiBackend path

**Files:** `pep/proxy/proxy.go`, `pep/proxy/backend_pdp.go`, tests.

- `Config.Routes []Route`; build the gateway in `New` (surface errors), store `s.gateway`; `Handler()` mounts
  `mux.Handle("/", s.gateway)` last when set. Remove the `apiBackend` interface + `mountAPI` call;
  drop `PDPConfig.APIPrefix/APIUpstream`.
- [ ] Tests: `/oauth2/*` wins over a `/` route; gateway reached for other paths; off when no routes.
- [ ] Guard 0. Commit: `feat(pep): mount the enforcer gateway; remove the single-/api path`.

### Task R7: cmd + docs

**Files:** `pep/cmd/zero-pep-proxy/main.go`, `CONFIG.md`, `pep/proxy/e2e/README.md`.

- `RoutesFromConfig()` (PEP_ROUTES_PATH YAML | env shortcuts) → `cfg.Routes`. Document `gate`/`scope`/`inject`
  + a `routes.yaml` example + the standalone shape replacing `zero-bff-pdp`.
- [ ] Build + vet. Commit: `feat(pep): wire gateway routes; document gate/scope`.

### Task R8: HITL (the bff-pdp replacement shape)

Per the stage-HITL rule. pep standalone, `/` identity (gate snapshot) + `/api` dpop (gate session), PDP backend
+ mock-IdP harness. Verify: unauthenticated `/` → login; after login `/` injected identity; `/api` →
zaddy-verified DPoP; unauthenticated `/api` → 401.

## Self-Review

- Spec coverage: gate/scope config (R1), EnforcerSessionCookie + shared open (R2), resolution + Context (R3),
  enforcer gating (R4), DPoP (R5), Server wiring (R6), cmd/docs (R7), HITL (R8).
- Risk flagged: `pepContext.setClaims` is a new in-package method (R2); the gateway resolves its own session
  rather than threading `*Session` through `pep.Context` (R3/R4) — the cleanest given the DPoP-stateful constraint.
