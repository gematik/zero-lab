# zero-pdp end-to-end testing

Developer-run, environment-guarded e2e tests for the `zero-pdp` authorization server. They run
against an **already-running** server (locally, or via a public tunnel) and are **skipped**
whenever `ZERO_PDP_E2E_URL` is unset — so `go test ./...` and CI stay green by default.

Tests live in `go/pdp/e2e/` (package `e2e`). Run from `go/`.

## Layers

| Suite | `-run` | What it checks |
| --- | --- | --- |
| Smoke | `Smoke` | server up; metadata, JWKS, `/nonce` (text/plain), `/openid_providers`, OIDF entity statement reachable & well-formed |
| Regression | `Regression` | stable contracts: metadata fields, OAuth JSON error shape (404/405/unsupported grant/bad content-type), `HEAD /nonce`→405 |
| Flows | `Flow` | partial-flow checkpoints (see rule) |
| HITL | `HITL` | full browser-login authorization-code flow (opt-in) |

**Success rule:** a non-HITL test asserts the furthest checkpoint reachable *without a human*
and treats that as success. For the OIDF/OIDC leg, a **successful pdp→IdP pushed authorization
request** (the `/authorization` redirect to the IdP carrying `request_uri`) is itself the
success criterion — the full login is only exercised in the HITL suite.

## Quick start (local)

```bash
cd go
# terminal 1 — start the server (generates sign.jwk + client-secret hash)
just pdp-e2e-serve            # issuer http://localhost:8011, client e2e-client / e2e-client

# terminal 2 — run the suites
just pdp-e2e-smoke            # smoke only
just pdp-e2e                  # smoke + regression + flows
```

`client_credentials` is exercised out-of-the-box (the testdata config defines a confidential
`e2e-client`). The authorization/PAR/HITL flows need an OpenID Provider configured (below).

## Public host (rathole) + OpenID Provider

OIDC/OIDF flows need the server reachable at a stable public issuer and an OP to drive.

1. Configure an OP in `go/pdp/e2e/testdata/pdp.e2e.yaml` (uncomment the `gematik_idp` /
   `oidc_providers` / `oidf_relying_party` block; values come from env via `os.ExpandEnv`).
2. Start a rathole tunnel exposing local `:8011` at `https://<public-host>`.
3. Serve with the public issuer and run against it:

```bash
just pdp-e2e-serve https://<public-host>
just pdp-e2e        https://<public-host>     # smoke + regression + flows (incl. pdp→IdP PAR)
just pdp-e2e-hitl   https://<public-host>     # opens a browser; complete the login
```

The HITL test starts a local capture server (`http://localhost:8765/callback`) as the client
`redirect_uri`; the human's local browser performs the final redirect there. Register that
redirect URI for the client and at the OP.

## Environment variables

| Var | Purpose | Default |
| --- | --- | --- |
| `ZERO_PDP_E2E_URL` | base URL / issuer; **unset ⇒ all e2e tests skip** | — |
| `ZERO_PDP_E2E_HITL` | enable the HITL suite | unset |
| `ZERO_PDP_E2E_CLIENT_ID` | OAuth client id | `e2e-client` |
| `ZERO_PDP_E2E_CLIENT_SECRET` | confidential client secret (must match the served hash) | `e2e-client` |
| `ZERO_PDP_E2E_SCOPE` | requested scope | `e2e` |
| `ZERO_PDP_E2E_OP_ISSUER` | OP issuer for the plain auth-code / HITL flow | `https://accounts.google.com` |
| `ZERO_PDP_E2E_FED_ISSUER` | OIDF federation IdP issuer for the federation PAR flow | `https://idbroker.tk.ru2.nonprod-ehealth-id.de` |
| `ZERO_PDP_E2E_REDIRECT_URI` | client redirect URI | `http://localhost:8765/as-callback` |
| `ZERO_PDP_E2E_CALLBACK_ADDR` | HITL capture listen address | `localhost:8765` |

Secrets are never committed: `sign.jwk` is generated and gitignored; the client secret is
hashed at serve time; OP credentials come from your environment / `.env` (loaded by the server).
