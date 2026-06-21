# pdp-bff — single-port relying-party demo

Runs the pdp authorization server, the bff, and the embedded webui as **one process on one port** — a
lightweight harness for debugging a relying party against directory-ref. Expose it publicly with a tunnel
(e.g. rathole pointed at port 8011); ingress and TLS are handled upstream (directory-ref Caddy), so this
binary speaks plain HTTP on one port. Because there is a single origin, the OAuth `issuer`, the public URL,
and the bff's own server-side calls all line up — no split-horizon to reconcile.

## How it routes (one mux, one port)
- `/.well-known/oauth-authorization-server`, `/.well-known/openid-federation`, `/as/*` → pdp (authorization server)
- `/bff/*` → bff API, `/` → webui

So the pdp config **must** keep operational endpoints under `/as` (well-knowns at root) — see
[`config/pdp.example.yaml`](config/pdp.example.yaml).

## Configure
1. Put your directory-ref pdp config in `./config/pdp.yaml` (start from `config/pdp.example.yaml`), plus
   `sign.jwk` and any OIDF relying-party keys it references:
   ```sh
   go run ./pdp/cmd/zero-pdp jose generate-jwk > config/sign.jwk
   ```
2. Register the bff as a client in the config and hash its secret:
   ```sh
   go run ./pdp/cmd/zero-pdp secret-hash "bff-demo"   # -> BFF_CLIENT_SECRET_HASH
   ```
3. Copy `.env.example` to `.env` and set `PUBLIC_URL` (your tunnel origin), `BFF_CLIENT_*`, `GOOGLE_*`.

## Run
```sh
docker compose up --build
# point rathole at port 8011, then browse $PUBLIC_URL
```
Or locally, without docker:
```sh
PDP_BFF_CONFIG=config/pdp.yaml BFF_PUBLIC_URL=http://127.0.0.1:8011 go run ./bff/cmd/pdp-bff
```

## What it demonstrates
The webui's provider picker lists every OP configured in the pdp — e.g. **Google** (`oidc_providers`) and the
**gematik directory** providers (`oidf_relying_party`) — combined behind one authorization server.

## Environment
| var | meaning |
|---|---|
| `PDP_BFF_CONFIG` | path to the pdp config (flag `--pdp-config`; default `pdp.yaml`, container `/config/pdp.yaml`) |
| `PUBLIC_URL` | public origin (tunnel URL); the config's `issuer` + redirect base |
| `BFF_PUBLIC_URL` / `BFF_AS_ISSUER` | the public origin (one URL = `PUBLIC_URL`) |
| `BFF_CLIENT_ID` / `BFF_CLIENT_SECRET` | the bff's credentials (must match the config's client + its hash) |
| `BFF_COOKIE_NAME` | session cookie name (default `ZETA-BFF-SID`) |
