# pep — backlog (goal: retire the bff)

The bff is redundant with pep once pep covers the gateway role. Audit finding: pep already **matches or
exceeds** the bff on the AS-client (pep adds PAR + DPoP-nonce retry), sessions (per-issuer token sets, at-rest
encryption, revocation bus, snapshot fast path, OWASP TTLs), and DPoP (per-session keys). The bff has **no
consumers** — nothing in the repo imports it and no external SPA calls `/bff/auth/*`; its SPA is internal to
its own binaries. So the only thing standing between us and deleting `bff/` is the reverse-proxy gateway.

Priority order below is the retire-the-bff path. Items 3–4 are independent and rank below it.

## 1. Gateway parity (S5) — the one removal blocker  ·  NEXT
Port `bff/gateway` into pep so it gates **and** reverse-proxies upstreams standalone (no Caddy required):
- **Multi-route reverse proxy** (not just `/api`): configurable upstreams + path prefixes + optional strip
  (the `RoutesFromEnv` shape), each with its own injection mode.
- **Identity-header injection**: `X-Auth-Request-Identity` = base64url(JSON claims), alongside the existing
  per-session DPoP injection.
- **HTML/API branching on unauthenticated**: browser (`Accept: text/html`) → 302 `/oauth2/sign_in`; API →
  JSON 401. Today pep returns a bare 401 and leans on Caddy's `handle_response` — this makes pep self-sufficient.
- Refs: `bff/gateway/{gateway,host,inject}.go`, `pep/proxy/{proxy.go,inject.go,backend_pdp.go}`. HITL-gated.

## 2. Cut over + delete the bff  ·  after 1
- Replace the **zero-bff-pdp** all-in-one demo (PDP authz server + bff + webui in one process) with
  `zero-pdp` + `zero-pep-proxy` as two services — the e2e harness already runs them side by side.
- Repoint build/deploy: justfile docker targets (`docker-*-bff-pdp`), the bff docker-compose, any deploy refs.
- Delete `bff/` (`bff.go`, `gateway/`, `session_manager*`, the webui SPA, `cmd/zero-bff{,-pdp}`, tests). No
  external consumers, so no deprecation window needed.
- Docs: redirect `/bff/auth/*` → `/oauth2/*`; note pep's server-rendered pages replace the bff SPA (no
  JSON-API compat mode is needed — there are no SPA consumers).

## 3. Cross-AS token acquisition  ·  not a blocker
pep already has per-issuer token sets + per-session DPoP. Add lazy multi-AS acquisition so one login mediates
DPoP-bound tokens for several resource servers. Independent of the bff removal.

## 4. Login / chooser UX  ·  ongoing
Error/retry pages, chooser refinements, `userinfo`/session views, accessibility (focus / reduced-motion), and
the close-tab / desktop-redirect edge cases on the decoupled + gemidp pages.

## Notes
- pep's PDP AS-client is a faithful port of the bff's **plus** PAR and nonce-retry — no parity work there.
- The all-in-one `zero-bff-pdp` was a single-port demo convenience; replacing it with two services (or one
  behind Caddy) is an ops change, not a pep functional gap.
