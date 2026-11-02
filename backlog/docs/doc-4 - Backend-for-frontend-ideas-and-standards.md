---
id: doc-4
title: 'Backend for frontend: ideas and standards'
type: other
created_date: '2026-11-02T20:15:00Z'
---

## Why this exists

`go/bff` was removed when `go/pep/proxy` covered the gateway role. Nothing imported it and it had no release consumer. This records what it did, so the ideas are not lost with the code. The last version is in git history before the commit that removed it.

## What it was

A Backend-For-Frontend: a confidential client of the authorization server that keeps tokens on the server and gives the browser only an opaque session cookie. `zero-bff-pdp` ran the PDP, the BFF and a web UI as one process on one port, a demo harness with one origin and so no split horizon between the public issuer and server-side calls.

## Standards

| Standard | Used for |
|---|---|
| draft-ietf-oauth-browser-based-apps | The BFF pattern itself |
| RFC 6749 | Authorization code flow and error format |
| RFC 7636 | PKCE with S256 |
| RFC 7523 | `private_key_jwt` client authentication, extended with the gematik `nonce` claim and `cnf.jkt` |
| RFC 8414 | Discovering the authorization server |
| RFC 7662 | Introspection, for the upstream identity |
| RFC 9449 | DPoP proofs on proxied API calls |
| RFC 6265bis | `__Host-` cookies with SameSite=Strict |

PAR was not in the BFF: the authorization server performed it. `pep/proxy` does PAR itself.

## Ideas worth keeping

- **CSRF by a required header:** state-changing API calls needed `X-Requested-With`, which a cross-site form cannot send and a cross-site `fetch` cannot send without a preflight.
- **JSON API instead of pages:** `/bff/auth/login`, `/session`, `/providers`, so an SPA owns all of its UI. pep renders its own pages, and no SPA consumer existed.
- **`SessionView`:** decoded token claims returned to the browser for display, never the tokens.
- **Library use:** `Protect` and `SessionFromContext`, for embedding the BFF in another Go server.
- **QR login with polling:** a second device completes the login while the first polls. pep carries this on (`pep/proxy/docs/DESIGN.md`, section 3).
- **Identity header to upstreams:** base64url JSON claims in `X-Auth-Request-Identity`, oauth2-proxy style. pep carries this on.

## Why pep differs

- **SameSite:** the BFF used Strict; pep uses Lax deliberately (`pep/proxy/cookie.go`), since Strict drops the cookie on the redirect back from a provider.
- **DPoP key:** the BFF had one process-wide key. pep has one per session, which limits what a stolen token set is worth.
- **Generated client keys:** `zero-bff-pdp` generated its keys and registered itself as a client. pep needs its client key supplied, which is right for anything but a demo.

## Known defect at removal

`zero-bff-pdp` logins were already broken: `bff.go` sent no DPoP proof to the token endpoint, while `pdp/authzserver/token.go` requires one when the assertion carries `cnf.jkt`.

## Replacement

`zero-pdp` and `zero-pep-proxy` in gateway mode as two services (`pep/proxy/e2e/README.md`). Running them behind one origin with `gate: none` routes for `/as` and `/.well-known` should work, but has not been tested.
