# bff — Backend-For-Frontend

An OAuth/OIDC Backend-For-Frontend per [draft-ietf-oauth-browser-based-apps][bcp]. The Go package is
an **API only**; a static, framework-free SPA in [`webui/`](webui) is the UI. The browser only ever
holds an opaque, `HttpOnly` session cookie — tokens stay in the BFF.

## Layout

- `bff` — the API (Go). Stdlib `net/http` routing, panic-recovery middleware.
- `bff/webui` — static SPA (`index.html` + `app.js` + `style.css`), embedded via `embed.FS`. Talks to
  the API over `/bff/auth/*` only, so it can be replaced by a React/Svelte build without touching the API.
- `bff/cmd` — a host that mounts the API and serves the SPA.

## API (`/bff/auth/*`)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/bff/auth/providers` | list the AS openid providers for the chooser |
| GET | `/bff/auth/login?idp_iss=` | start login; JSON `{auth_url, mode, op}` (`mode` = `redirect` or, for OIDF, `decoupled`); binds the browser to a pending session |
| GET | `/bff/auth/callback` | OAuth redirect_uri: exchange code, introspect for identity, set session cookie |
| GET | `/bff/auth/poll` | `202` while pending, `200` once authenticated (decoupled/QR flow) |
| GET | `/bff/auth/session` | `{authenticated, userinfo}` for the current session |
| POST | `/bff/auth/logout` | clear the session (requires `X-Requested-With` — CSRF defense) |

To put the BFF *in front of* a real application — gating it and forwarding identity/tokens — see
[**Gateway**](#gateway) below.

Identity is taken from the AS **token introspection** endpoint (RFC 7662): the BFF — a confidential
client — introspects its own access token and reads the `identity` extension (the upstream id_token
claims). For OIDF providers the SPA shows a **QR code** of `auth_url` and polls until a second device
completes the login.

## Gateway

`bff/gateway` turns the BFF into an **oauth2-proxy-style auth gateway**: it gates and reverse-proxies a
set of upstreams that run as **separate containers** behind it, so the business webapp never sees a token
and is never reachable un-authenticated. The login UI + auth API stay BFF-owned; everything else is
proxied. It is a **mode of the existing hosts** (`zero-bff`, `zero-bff-pdp`), enabled by setting
`WEBAPP_UPSTREAM` / `API_UPSTREAM` — unset, the host serves the classic login UI at `/`. Routing in
gateway mode:

| Path | Goes to | Gated |
| --- | --- | --- |
| `/.well-known/*`, `/as/*` | the authorization server (`zero-bff-pdp` only) | no |
| `/bff/auth/*` | the BFF auth endpoints | no |
| `/bff/` | the BFF's stock login UI (`webui`) | no |
| `/api/` | the API resource server (proxied) | yes — inject **DPoP** token |
| `/` | the business webapp (proxied) | yes — inject **identity** header |

A protected request with no valid session is **redirected** to `/bff/?rd=<original>` for an HTML
navigation, or gets a JSON **401** for an XHR/API call. Authenticated requests are proxied with a fresh
access token (auto-refreshed) and, per route's `Inject`:

- **identity** — `X-Auth-Request-Identity: base64url(JSON(identity claims))`, a single header (the upstream
  trusts the gateway; the gateway strips any client-spoofed copy). No token leaves the gateway.
- **dpop** — `Authorization: DPoP <access_token>` plus a per-request `DPoP` proof minted with the BFF's
  DPoP key (the token is `cnf.jkt`-bound to it), for a resource server that enforces RFC 9449.

### Run the gateway demo

The `zero-bff-pdp` compose runs the AS + gateway in one process, fronting two `httpbun` containers (a
webapp + an API) that echo the injected headers, plus Postgres for durable sessions:

```bash
cd go/bff/cmd/zero-bff-pdp
cp config/.env.example .env && $EDITOR .env   # set PUBLIC_URL (your tunnel) + an OIDC provider
go run ../../../pdp/cmd/zero-pdp jose generate-jwk > config/sign.jwk
docker compose up --build
```

Open `PUBLIC_URL`, sign in, then `GET /headers` (the webapp) echoes the `X-Auth-Request-Identity` header,
and `GET /api/headers` (the API, prefix stripped) echoes `Authorization: DPoP …` + the proof — proving
injection reached the separate containers.

## Run the demo

The BFF is a confidential client; register `<BFF_PUBLIC_URL>/bff/auth/callback` as its redirect_uri at
the authorization server.

```bash
cd go
BFF_AS_ISSUER=https://directory-ref.ccs.gematik.solutions \
BFF_CLIENT_ID=e2e-client \
BFF_PUBLIC_URL=http://127.0.0.1:8080 \
go run ./bff/cmd/zero-bff
```

Open `http://127.0.0.1:8080`, pick the **TK RU2** OIDF provider, scan the QR on a second device to log
in, and the page shows your identity.

[bcp]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
