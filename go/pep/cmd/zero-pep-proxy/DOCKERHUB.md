# zero-pep-proxy

An **oauth2-proxy-style authentication gateway** for the [gematik Zero Trust Lab](https://github.com/gematik/zero-lab).
It runs the login (direct **OIDC**, gematik **OpenID Federation / OIDF**, or the gematik **IDP-Dienst /
gemidp**), keeps tokens server-side (token-mediating BFF — tokens never reach the browser), and gates upstream
traffic via the standard `/oauth2/*` + `/oauth2/auth` forward_auth contract. It drops in behind **Caddy**
`forward_auth`, **ingress-nginx** (`auth-url`/`auth-signin`), or **Traefik** `ForwardAuth`.

- `scratch` image, runs **non-root** (uid 65532), structured logs.
- Encrypted **session-snapshot** fast path: `/oauth2/auth` validates locally — **no DB read per request** —
  with **instant fleet-wide revocation** over Postgres `LISTEN/NOTIFY` and a durable backstop. Survives
  restarts and scales horizontally.

## Run

```sh
docker run -p 4180:4180 \
  -e PEP_PUBLIC_URL=https://your.host \
  -e DATABASE_URL='postgres://user:pass@db:5432/zero?sslmode=disable' \
  -e PEP_SESSION_KEY_PATH=/run/secrets/session.key \
  -v "$PWD/openid-providers.yaml:/app/openid-providers.yaml:ro" \
  -v "$PWD/session.key:/run/secrets/session.key:ro" \
  spilikin/zero-pep-proxy:latest
```

- **Providers** come from `openid-providers.yaml` (`oidc:` / `gemidp:` / `oidf:`); mount it at
  `/app/openid-providers.yaml` or point `PEP_OPENID_PROVIDERS_PATH` at it. A single provider can instead come
  from `PEP_OIDC_ISSUER` / `PEP_OIDF_RP_CONFIG_PATH` / `PEP_GEMIDP_CLIENT_ID`.
- **Everything else is env:** `PEP_ADDR` (`:4180`), `PEP_PUBLIC_URL`, `PEP_PRODUCTION_COOKIE` (`true` behind
  HTTPS), `DATABASE_URL` (Postgres session store; in-memory if unset), `PEP_SESSION_KEY_PATH` (base64 256-bit
  key file → enables the snapshot fast path), `PEP_SESSION_TTL` (default `8h`).
- **Secrets are files**, mounted and referenced by `*_PATH` — never baked into the image or passed as values.

Full configuration reference (every parameter, the providers-file vs env split):
[`go/pep/cmd/zero-pep-proxy/CONFIG.md`](https://github.com/gematik/zero-lab/blob/main/go/pep/cmd/zero-pep-proxy/CONFIG.md).

## Tags

- `latest` — the most recent build.
- `X.Y.Z` — pinned, matching the `go/pep/vX.Y.Z` source tag.

## Source

https://github.com/gematik/zero-lab — issues and docs.
