# zero-pep-proxy

An oauth2-proxy-style authentication gateway for the [gematik Zero Trust Lab](https://github.com/gematik/zero-lab).
It runs the login (direct OIDC, gematik OpenID Federation / OIDF, or the gematik IDP-Dienst / gemidp), keeps
tokens server-side (token-mediating BFF — tokens never reach the browser), and gates upstream traffic via the
standard `/oauth2/*` + `/oauth2/auth` forward_auth contract — behind Caddy, ingress-nginx (`auth-url`), or
Traefik ForwardAuth.

`scratch` image, non-root (uid 65532), structured logs. Optional encrypted session-snapshot fast path:
`/oauth2/auth` validates locally with no DB read per request, with instant fleet-wide revocation over Postgres
`LISTEN/NOTIFY`.

## Run

Simplest — in-memory sessions, one OIDC provider, no database:

```sh
docker run -p 4180:4180 \
  -e PEP_PUBLIC_URL=https://your.host \
  -e PEP_OIDC_ISSUER=https://accounts.google.com \
  -e PEP_OIDC_CLIENT_ID=... -e PEP_OIDC_CLIENT_SECRET=... \
  spilikin/zero-pep-proxy:latest
```

For several providers, mount your config dir at `/etc/pep` — `openid-providers.yaml` (with `oidc:` /
`gemidp:` / `oidf:`) and any secrets live there.

## Configuration

All via environment; secrets are mounted files referenced by a `*_PATH`, never baked in or passed as values.
Full reference: [CONFIG.md](https://github.com/gematik/zero-lab/blob/main/go/pep/cmd/zero-pep-proxy/CONFIG.md).

| Var | For | Default |
| --- | --- | --- |
| PEP_PUBLIC_URL | public origin the browser uses (the front) | http://127.0.0.1:4180 |
| PEP_ADDR | listen address | :4180 |
| PEP_INSECURE_COOKIE | `"true"` drops `__Host-`/Secure for `http://localhost` dev; secure by default | false |
| PEP_OIDC_ISSUER (+ _CLIENT_ID/_CLIENT_SECRET) | one OIDC provider | — |
| PEP_OIDF_RP_CONFIG_PATH | a gematik OIDF relying party | — |
| PEP_GEMIDP_CLIENT_ID | a gematik IDP-Dienst client | — |
| PEP_OPENID_PROVIDERS_PATH | several providers (a YAML file) | ./openid-providers.yaml |
| DATABASE_URL | durable, shared sessions (Postgres) | in-memory |
| PEP_SESSION_KEY_PATH | session-snapshot fast path (no DB per request) | off |
| PEP_SESSION_TTL | session lifetime with the fast path | 8h |

## Tags

- `latest` — most recent build
- `X.Y.Z` — pinned, matching the `go/pep/vX.Y.Z` source tag

## Source

https://github.com/gematik/zero-lab
