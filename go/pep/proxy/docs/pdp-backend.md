# pep/proxy — PDP backend (S4) design

This is the design for **S4** of the pep oauth2-proxy plan: a second `Backend` that makes pep a confidential
**BFF client of the PDP** (the gematik authorization server, `zero-pdp`), obtaining DPoP-bound access tokens
and injecting them into protected upstream APIs. It is the bff's AS-client + gateway-injection logic, **ported**
into `pep/proxy` (the bff stays intact until S7).

## 1. Grounding & scope

### BCP pattern
pep is a **Backend-For-Frontend** in the sense of `draft-ietf-oauth-browser-based-apps` — the *strongest* of
the BCP's three patterns: access/refresh tokens **never reach the browser**, and pep proxies + injects on the
server. This is distinct from the BCP's **Token-Mediating Backend** (where the access token *does* reach the
browser), for which the BCP rules DPoP "out of scope." Because the PDP flow is DPoP-bound, pep must be a BFF.
(`DESIGN.md §1` currently conflates the two terms — S4 fixes that wording.)

### What S4 delivers
- `pdpBackend` implementing `Backend`: login via the PDP (auth-code + `private_key_jwt` + DPoP + PKCE),
  code exchange, introspection, refresh.
- **Per-session DPoP keys** (not a process-wide key).
- A gated **`/api` reverse-proxy** that injects `Authorization: DPoP <token>` + a fresh proof.
- Config + session structures that **support several ASes / several APIs** (binding list), exercised in S4's
  HITL with **one** binding.
- **HITL**: login via a local `zero-pdp`, then `GET /api/protected-dpop` reaches a `zaddy` resource server
  that **verifies the DPoP proof** → `200`. Real DPoP, end to end, local.

### Decisions (this planning session)
- The PDP backend is **mutually exclusive** with the provider backend, selected by `PEP_BACKEND=pdp`. In PDP
  mode the direct OIDC/OIDF/gemidp providers are off; the chooser lists the *AS's* providers.
- Reuse strategy: **port** into `pep/proxy` (no shared package); bff is deprecated in S7.
- Multi-AS login: **one login + lazy per-API tokens** (see §5).
- Hardening is staged. Per-session DPoP keys ship in S4. At-rest encryption / refresh rotation are a near-term
  follow-on. The committed **T3 target is the browser-held DPoP hybrid** — the proof-of-possession key lives in
  the browser, not pep, so a compromised pep cannot forge proofs — built as its **own stage after S4** behind a
  signer seam (see §4, §10).
- Everything browser-side is **unchanged**: session, opaque `__Host-` cookie, `/oauth2/*`, the qr/poll
  decoupled UI, the forward_auth gate, and the snapshot fast path. Only the backend behind them differs.

## 2. Architecture

```
browser ──cookie──> pep (pdpBackend)
                     │  login: auth-code + private_key_jwt(cnf.jkt=session DPoP key) + DPoP
                     ├──────────────> primary AS = zero-pdp  (token + refresh + introspect)
                     │
   GET /api/...      │  gated reverse-proxy: FreshAccessToken(binding) → Authorization: DPoP <tok>
   (cookie) ────────>│  + DPoP proof (htm/htu/ath, session key) ──> upstream resource (zaddy)
                                                                       enforce_policy verifies proof → 200
```

pep is the confidential OAuth client; tokens live server-side in `kv`; the browser only carries the opaque
session cookie.

## 3. Login flow — `backend_pdp.go` (port of the bff AS-client)

Implements `Backend`:

- `Providers(ctx)` → fetch the AS's openid-provider list (the chooser).
- `DefaultIssuer()` → `""` (chooser) or a single configured provider.
- `StartLogin(ctx, sess, idpIss, scope)` → generate the **per-session DPoP keypair** (§4), set
  `state`/`nonce`/PKCE on the session, build the AS authorization request. For OIDF providers the AS performs
  PAR, so pep resolves the decoupled auth URL in the backend (`resolveDecoupledAuthURL`) and returns
  `Mode: decoupled` → pep's existing `qr.html` + `/oauth2/poll`. Otherwise `Mode: redirect`.
- `Complete(ctx, sess, code)` → exchange the code at the AS token endpoint with a **`private_key_jwt`**
  client assertion (RFC 7523 §2.2: `iss=sub=client_id`, `aud=issuer`, a fresh AS **nonce**,
  `cnf.jkt` = the **session** DPoP-key thumbprint) **plus a DPoP header**; store the access+refresh tokens in
  the session's token set under the primary AS; **introspect** (RFC 7662) → `sess.Identity`.
- `FreshAccessToken(ctx, sess, asIssuer)` → return a non-expired token for that AS, refreshing
  (client-authenticated) and persisting as needed.

Ported bff functions: `discoverMetadata` (RFC 8414), `fetchNonce`, `clientAssertion`, the code exchange,
`introspectIdentity`, `FreshAccessToken`, `resolveDecoupledAuthURL`. No `pdp` import — pep talks to the AS
over HTTP (RFC 8414 + `golang.org/x/oauth2`), exactly as the bff does.

## 4. Per-session DPoP keys

Each session owns its DPoP keypair, generated at `StartLogin`:
- `cnf.jkt` in the client assertion (and thus the token binding) is the **session** key's thumbprint.
- `/api` proofs are minted with the **session** key.
- The private key is **session state** (serialized JWK in the `kv` session), not a process-wide
  `*_PATH` key.

Blast radius drops from "every session shares one key" to one session. The `Backend.DPoPKey()` method (today a
single process key) is removed; the injector reads the key from the session. In S4 the key is stored in `kv`
**unencrypted** with a `TODO` pointing at the at-rest-encryption follow-on (§10) — a known, documented gap.

**Signer seam (forward-looking).** Proof generation goes behind a `sessionSigner` interface so the key holder
is pluggable. S4's signer is the BFF-held key above. The **T3 stage** (§10) swaps in a **browser-relayed**
signer where the private key lives in the browser and pep only ever holds the session's DPoP *public* JWK. The
session stores the public JWK regardless, so the swap is additive — not a rewrite. This is the one place S4's
shape is chosen to make T3 reachable.

## 5. Several ASes / several APIs

Config is a list of **API bindings**:

```
binding = { prefix, upstream, as_issuer, client_id, signing_key_path, scopes }
```

A request to `<prefix>/*` injects the token from *that binding's* AS. The session holds a **token set keyed by
AS issuer** (`access`, `refresh`, `expiry` per AS).

**Login model — one login, lazy per-API tokens:**
- The user logs into one **primary AS** (identity + session); its token is obtained at `Complete`.
- For a route whose binding AS **is** the primary AS (the common case, and all of S4's HITL), the login token
  is used directly.
- For a route whose binding AS **differs**, the token is acquired **lazily on first access** — either a fresh
  auth-code leg to that AS or **RFC 8693 token-exchange** from the primary token where the AS supports it —
  then cached in the session's token set.

**S4 vs later:** S4 builds the binding-list config, the per-AS token-set session, and the injector that selects
the matched binding's token. S4's HITL exercises **one** binding where the API's AS *is* the login AS, so no
cross-AS acquisition runs. The cross-AS lazy-acquisition path (auth-code leg vs RFC 8693 — to be chosen when it
lands) is specified here but implemented + HITL-proven in a **follow-on stage** (it needs a second AS to test).

## 6. DPoP `/api` injection — `inject.go` (port of `bff/gateway`)

pep mounts a **gated reverse-proxy** per binding (`<prefix>/*` → `upstream`). Per request:
1. Resolve the session (cookie). No valid session → `401` for XHR / redirect to `/oauth2/start?rd=` for a
   navigation.
2. `FreshAccessToken(sess, binding.as_issuer)` (refresh if needed).
3. **Delete any inbound `Authorization`** (strip client-spoofed headers).
4. Set `Authorization: DPoP <token>`.
5. Mint a DPoP proof — `htm`/`htu` = the **actual** outbound method+URL, `ath` = access-token hash — with the
   **session** DPoP key, set the `DPoP` header.
6. Proxy to `upstream` (strip the route prefix).

**BCP allowlist MUST** ("validate destination hosts before forwarding"): the binding's `upstream` is the only
permitted destination for that route — an explicit, per-binding allowlist. The proxy never forwards elsewhere.

DPoP binding is correct by construction because **pep makes the outbound request**, so `htm`/`htu` match the
real request (this is why injection is a reverse-proxy, not forward_auth response headers).

## 7. Session model

`Session` gains (PDP backend only; provider backend leaves them zero):
- a **token set** keyed by AS issuer: `{ access_token, access_token_expires_at, refresh_token }` per AS;
- the **session DPoP key** (serialized JWK).

Snapshot interaction: the forward_auth fast path is **unchanged** — the encrypted snapshot carries identity,
not tokens, so the gate stays `kv`-free. The `/api` path is a data-path that reads the session from `kv` (it
needs the token and may refresh), which is fine — it's the resource call, not the gate.

## 8. Config (env)

```
PEP_BACKEND=pdp                         # select the PDP backend (mutually exclusive)
PEP_AS_ISSUER                           # primary AS (login/identity)
PEP_CLIENT_ID
PEP_CLIENT_SIGNING_KEY_PATH             # private_key_jwt signing key (file)
PEP_REDIRECT_URI                        # default <public>/oauth2/callback
# one or more API bindings (primary AS may be reused as a binding's AS):
PEP_API_<n>_PREFIX        (default /api for n=1)
PEP_API_<n>_UPSTREAM
PEP_API_<n>_AS_ISSUER     (default = PEP_AS_ISSUER)
PEP_API_<n>_CLIENT_ID / _SIGNING_KEY_PATH / _SCOPES   (default = primary)
```

Keys are read from `*_PATH` files, never env values (project rule). DPoP keys are **per session**, not config.
Exact env shape (indexed vs a YAML bindings file) is an implementation detail to confirm in the plan.

## 9. Stages & boundary

- **PDP alignment (precursor to S4)** — bring `zero-pdp` to pep's conventions: providers via the shared
  `openid-providers.yaml`, server/secrets via env + `*_PATH`, the `/app` binary + `/etc/pdp` workdir Docker
  pattern, `just docker-build/push-pdp` + version stamp, `CONFIG.md`/`DOCKERHUB.md`, secure defaults; **bake in
  a mock IdP** (extend `NonProdMode`); put the PDP **in compose**. Its own stage/PR + spec
  ([`pdp/docs/pep-alignment.md`](../../../pdp/docs/pep-alignment.md)). S4's airgapped harness depends on it.
- **S4** (this doc): `pdpBackend`, per-session DPoP keys, the binding-list config + per-AS token-set session,
  and **one** gated `/api` DPoP reverse-proxy. Done = the §11 HITL.
- **S5**: generalize to the full gateway — webapp **identity** injection alongside DPoP, multi-binding
  `RoutesFromEnv`, `handleUnauthenticated`, header hygiene at scale. S4 builds the injection primitive; S5
  makes pep the gateway.
- **T3 — browser-held DPoP** (own stage, after S4): move the per-session PoP key into the browser so a
  compromised pep cannot forge proofs (§10). Spike-first (the decoupled flow). Near-term in between: at-rest
  encryption of the per-session key + refresh token, and refresh-token rotation.

## 10. Hardening roadmap & the "don't trust the BFF" analysis

| tier | threat | mitigation |
| --- | --- | --- |
| T0 | XSS in the SPA | `HttpOnly` cookie (done); XSS can still *drive* the BFF — unavoidable per BCP |
| T1 | cookie exfiltration | `__Host`/`Secure`/`HttpOnly` (done) + sender-constrained tokens (S4); device-bound cookies (DBSC) to stop cookie replay — emerging, Chrome-only as of early 2026 |
| T2 | session-store (`kv`) dump | **near-term:** encrypt the per-session DPoP key + refresh token at rest (reuse the snapshot `*_PATH` key infra) + refresh-token rotation; short TTLs + revocation (done) |
| T3 | BFF process fully owned | **committed: browser-held DPoP hybrid (below)** — the PoP key never lives in pep |

Standards: DPoP (RFC 9449, per-session — **in S4**), OAuth Security BCP (RFC 9700 — refresh rotation, short
tokens), mTLS-bound tokens (RFC 8705 — alternative), **FAPI 2.0 Security Profile** (the high-security north
star), PAR (RFC 9126 — already used by the gematik OPs). Dead end: Token Binding (RFC 8471–8473).

### T3 — browser-held DPoP hybrid (committed target, own stage after S4)

The only real defence when pep itself is untrusted is to put the proof-of-possession key **out of pep**. Token
stays server-side (still a BFF); the DPoP key lives in the browser (non-extractable WebCrypto), so a
compromised pep holds the token but **cannot forge a proof**.

- **Token acquisition:** the browser signs the token-endpoint DPoP proof; pep relays it; the AS binds the
  token with `cnf.jkt` = the **browser** key. (pep still authenticates as the confidential client via
  `private_key_jwt` — orthogonal.)
- **Per call:** pep hands the browser just `ath = SHA256(access_token)` (a hash — safe) + the upstream `htu`;
  the browser signs `{htm, htu, ath, jti, iat}`; pep attaches `Authorization: DPoP <token>` + the browser's
  proof and forwards.
- pep slots this in via the **`sessionSigner` seam** (§4): the signer becomes "relay to the browser" instead
  of "BFF key."
- **Session binding (same key, no extra credential):** bind the *session cookie* to the same browser key —
  each request carries a proof over a **server-issued nonce** (RFC 9449 §8 style), verified against a
  session-level `cnf` recorded at login. A stolen cookie without the key is then useless (a
  **sender-constrained session**), closing T1's cookie-replay gap that `__Host`/`HttpOnly` can't. The nonce is
  only freshness/anti-replay — the *binding* is the key; a nonce alone (in a cookie or JS) leaks with the
  session. So T3 binds the access token and the session in one mechanism.

**Open problems the stage must solve (spike first):**
1. **Decoupled / QR flow** — the token must bind to the *polling* device's key, but the code arrives on the
   *completing* device. pep stores the code at the callback and **defers the token exchange to the next poll**,
   where the polling browser supplies its token-endpoint proof. Real poll-path redesign.
2. **Callback signing + DPoP nonce** — the redirect callback renders a JS step that signs the token-endpoint
   proof, including the AS's DPoP-nonce challenge round-trip.
3. **Trusted SPA delivery** — if a compromised pep *serves* the signing client it can serve malicious JS, so
   the client must come from a separate trusted origin (CDN + SRI + strict CSP) or a native app.
4. **Confused deputy** — the SPA must derive `htu` from user intent, not from pep's claim, or a compromised pep
   redirects a signature to another upstream.
5. **Navigation coverage** — JS can sign `fetch`/XHR but not top-level navigations, so app-level session
   binding covers API calls, not page loads; full navigation coverage needs **DBSC** (browser-native cookie
   binding). App-level now, DBSC when it matures.

This trades pep's **transparent-gateway** property (any app gated without code) for app cooperation (a
client-side proof SDK). That cost is why it is a dedicated, spike-first stage rather than part of S4.

## 11. HITL harness — fully airgapped (`pep/proxy/e2e`)

A self-contained `docker compose` with **zero network egress**:
- **`zero-pdp`** — the AS, **in compose** (built image), running `NonProdMode` with a **baked-in mock IdP**
  (delivered by the PDP-alignment stage, §9): the authorization flow auto-completes with a canned test
  identity instead of redirecting to a real OP. Issues DPoP-bound tokens; Postgres (or in-memory) alongside.
- **pep** — `PEP_BACKEND=pdp`, `PEP_AS_ISSUER=<zero-pdp in compose>`, client signing key, one binding
  `/api → zaddy`.
- **`zaddy`** — resource server with `enforce_policy { authorization_dpop; scope … }` on `/protected-dpop`,
  which **verifies** the DPoP proof.
- **front (Caddy)** — `/oauth2/*` and `/api/*` → pep.

**Proof:** browser → login via `zero-pdp` (mock IdP, per-session DPoP key, `cnf.jkt`-bound token) → session →
`GET /api/protected-dpop` → pep injects `Authorization: DPoP` + proof → **zaddy verifies → 200**. A tampered or
absent proof → rejected. No external IdP, no internet — the whole chain is local. The human drives it before S5.

The PDP is containerized + given the mock IdP by the **PDP-alignment stage** (precursor, §9 /
[`pdp/docs/pep-alignment.md`](../../../pdp/docs/pep-alignment.md)).

## 12. BCP / RFC compliance map

| requirement | where |
| --- | --- |
| BFF = confidential client (MUST) | `private_key_jwt` (RFC 7523) + `cnf.jkt` to the AS |
| Authorization Code + PKCE (MUST) | `StartLogin`/`Complete`, `S256` |
| `state`/`nonce` CSRF + correlation | session `state`/`nonce` (RFC 6749 §10.12, RFC 9700) |
| identity bound to session at login | OIDC `nonce` (id_token↔auth-request), `state` (callback↔session), session-id rotation on auth (anti-fixation); the per-request session-to-browser binding is the T3 stage (§10) |
| `Secure`+`HttpOnly` cookie (MUST), `__Host`/`SameSite` (SHOULD) | existing cookie template (secure by default) |
| CSRF on token-bearing endpoints | `SameSite=Lax` + `X-Requested-With` on state-changing routes |
| refresh server-side; session ≤ refresh lifetime | token set in `kv`; TTL note in the plan |
| sender-constrained tokens (DPoP) | per-session DPoP key; proof on every `/api` call |
| validate destination before forwarding (MUST) | per-binding `upstream` allowlist |
| tokens never reach the browser | BFF; cookie holds only the session id |

## 13. Verification

- **Unit:** `clientAssertion` (`cnf.jkt` = session key, fresh nonce); DPoP proof (`htm`/`htu`/`ath`); refresh;
  token-set selection by AS; injector strips inbound `Authorization` and sets `DPoP`; per-binding allowlist
  rejects an off-allowlist destination.
- **e2e/HITL:** §11, human-driven.
- **Module graph:** unchanged — `zero-caddy` stays free of `oidf/gemidp/kv/pep-proxy`
  (`go list -deps ./zaddy/cmd/zero-caddy | grep -c …` == 0). `zaddy` is the *resource server* in the HITL (a
  separate process), not an importer of `pep/proxy`.

## 14. Files

- **New:** `pep/proxy/backend_pdp.go` (AS-client), `pep/proxy/inject.go` (DPoP proof + reverse-proxy),
  e2e harness additions (compose: `zero-pdp` + `zaddy` + pep; the `/api` route).
- **Modify:** `pep/proxy/session.go` (per-AS token set + session DPoP key), `pep/proxy/backend.go`
  (drop process-wide `DPoPKey()`; per-session key), `pep/proxy/proxy.go` (mount the gated `/api` proxy/proxies),
  `pep/cmd/zero-pep-proxy/main.go` (PDP config + backend select + bindings), `DESIGN.md` (BFF vs
  token-mediating wording).
