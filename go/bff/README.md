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
| GET | `/bff/auth/login?op_issuer=` | start login; JSON `{auth_url, mode, op}` (`mode` = `redirect` or, for OIDF, `decoupled`); binds the browser to a pending session |
| GET | `/bff/auth/callback` | OAuth redirect_uri: exchange code, introspect for identity, set session cookie |
| GET | `/bff/auth/poll` | `202` while pending, `200` once authenticated (decoupled/QR flow) |
| GET | `/bff/auth/session` | `{authenticated, userinfo}` for the current session |
| POST | `/bff/auth/logout` | clear the session (requires `X-Requested-With` — CSRF defense) |

`/bff/api/*` is reserved for a future token-injecting resource-server proxy.

Identity is taken from the AS **token introspection** endpoint (RFC 7662): the BFF — a confidential
client — introspects its own access token and reads the `identity` extension (the upstream id_token
claims). For OIDF providers the SPA shows a **QR code** of `auth_url` and polls until a second device
completes the login.

## Run the demo

The BFF is a confidential client; register `<BFF_PUBLIC_URL>/bff/auth/callback` as its redirect_uri at
the authorization server.

```bash
cd go
BFF_AS_ISSUER=https://directory-ref.ccs.gematik.solutions \
BFF_CLIENT_ID=e2e-client BFF_CLIENT_SECRET=e2e-client \
BFF_PUBLIC_URL=http://127.0.0.1:8080 \
go run ./bff/cmd
```

Open `http://127.0.0.1:8080`, pick the **TK RU2** OIDF provider, scan the QR on a second device to log
in, and the page shows your identity.

[bcp]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
