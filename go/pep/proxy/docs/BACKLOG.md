# pep — backlog

Candidate next steps, parked. Not prioritized; pick one and brainstorm it into a spec when ready.
Done so far: S1–S4 of the staged build (OIDC / OIDF / gemidp / PDP backend), DPoP, mandatory PAR client,
the provider chooser + decoupled-page UX (pep `v0.25.x`).

## S5 — reverse-proxy mode + injection
Make pep gate **and** reverse-proxy upstreams itself, so it runs standalone without Caddy in front (an
oauth2-proxy lookalike on its own port). Port `bff/gateway`: `InjectIdentity` / `InjectDPoP`, request/response
header hygiene, `handleUnauthenticated`, and `WEBAPP_UPSTREAM` / `API_UPSTREAM` route config
(`RoutesFromEnv` shape). The next staged-build step.
- Refs: `bff/gateway/{gateway,inject,host}.go`, the plan `pep/proxy/docs/pdp-backend-plan.md` (S5).
- Note: this also unblocks the standalone `/` 404 we hit during HITL — a configured upstream serves `/`.

## Cross-AS token acquisition
S4 shipped a **single** AS binding. Add lazy multi-AS token acquisition + a per-AS token-set on the session,
so one login can mediate DPoP-bound tokens for several resource servers (each its own AS) without re-auth.
- Refs: `pep/proxy/docs/pdp-backend.md` (binding-list config), `pep/proxy/backend_pdp.go`.

## Login / chooser UX
Build on the recent chooser + decoupled work: error/retry pages, chooser refinements, the `/oauth2/userinfo`
+ session views, accessibility (focus/reduced-motion), and the close-tab / desktop-redirect edge cases on the
decoupled + gemidp pages.

## Deprecate the bff (S7)
Repoint `zero-bff*` / successor commands at `pep/proxy`, mark the `bff` module deprecated, and plan its
removal now that pep covers the token-mediating BFF role.
- Refs: the plan (S7), `bff/`.

## Smaller threads
- `/api` reverse-proxy is gated to a single upstream today; generalize alongside S5.
- Operator docs: a CONFIG note that PDP-backend clients must use PAR (direct `/authorize` is rejected since
  `zero-pdp` v0.22.0).
