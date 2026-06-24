# pep/proxy — design & references

`pep/proxy` is an oauth2-proxy-style authentication gateway: it runs the OAuth/OIDC login, keeps the tokens
server-side, and gates upstream traffic (forward_auth or reverse-proxy). This note records the design of the
**session + decoupled-login + polling** machinery and the standards / best practices it follows.

## 1. Token-mediating backend (the "BFF" pattern)

The browser never holds tokens. `/oauth2/start` creates a **server-side session** (in `kv`) and binds the
browser to it with an opaque, `HttpOnly` cookie holding only the session id; access/refresh tokens and the
identity live server-side. This is the **Token-Mediating Backend** profile of:

- **OAuth 2.0 for Browser-Based Applications** — `draft-ietf-oauth-browser-based-apps` (IETF OAuth BCP). The
  BFF keeps tokens out of JavaScript and mediates them on the backend.

The session cookie follows standard cookie hardening:

- **RFC 6265bis** (*Cookies: HTTP State Management Mechanism*) — `__Host-` prefix, `Secure`, `HttpOnly`,
  `SameSite`. We use `SameSite=Lax` deliberately (see §4) and `__Host-`+`Secure` in production.
- **OWASP Session Management Cheat Sheet / ASVS v4 (V3 Session Management)** — opaque high-entropy session
  id (KSUID), server-side state, sliding idle TTL, `HttpOnly`.

The authorization-code flow itself:

- **RFC 6749** (*OAuth 2.0*) + **RFC 7636** (*PKCE*, `S256`) + **RFC 9700** (*OAuth 2.0 Security Best Current
  Practice*). The `state` parameter is the per-login CSRF/correlation nonce (RFC 6749 §10.12, RFC 9700).

## 2. forward_auth gate + identity headers

`/oauth2/auth` is a subrequest endpoint: `202` + identity headers when the cookie resolves an authenticated
session, bare `401` otherwise. This is the **external/subrequest authorization** pattern:

- nginx `ngx_http_auth_request_module` and **Caddy `forward_auth`** — a reverse proxy calls an auth endpoint
  per request and forwards/denies based on its status.
- The `X-Auth-Request-User` / `-Email` / `-Groups` (+ our `X-Auth-Request-Identity`) header names follow the
  **oauth2-proxy** convention so pep is drop-in compatible with existing Caddy/nginx snippets.

## 3. Decoupled (cross-device) login + polling

For providers where the authorization completes **out-of-band** — OIDF on a second device via a scanned QR,
or gemidp via the gematik Authenticator app — the originating browser cannot follow a single redirect chain.
Instead it lands on a wait page (`qr.html` / `authenticator.html`) that **polls** `/oauth2/poll` until the
session becomes authenticated, then navigates to the return-to target.

This decoupled-and-poll shape is **modeled on** (not a literal implementation of) the standardized
cross-device flows:

- **RFC 8628** (*OAuth 2.0 Device Authorization Grant*) — the canonical "show a code/QR here, authorize on
  another device, **poll** until done" pattern. Our `/oauth2/poll` returning `202`
  (`authenticated:false`, i.e. RFC 8628 `authorization_pending`) vs `200` (`authenticated:true`) mirrors its
  token-endpoint polling (RFC 8628 §3.4–3.5). We differ in that pep polls *its own* session, not a device
  token endpoint.
- **OpenID Connect CIBA** (*Client-Initiated Backchannel Authentication*) — decoupled authentication with
  **poll / ping / push** token delivery. pep's wait-page polling is the spirit of CIBA **poll mode**, with
  the authorization result arriving via the redirect/callback rather than a CIBA backchannel response.

### Correlation: cookie for the browser, `state` for the callback

The decoupled flow has two independent channels that must be tied to the same session:

| channel | who | correlates by |
| --- | --- | --- |
| **poll** (`/oauth2/poll`) | the waiting browser (1st device / tab) | the **session cookie** set at `/oauth2/start` |
| **completion** (`/oauth2/callback?code&state`) | the 2nd device (OIDF QR) or the Authenticator app (gemidp) | the OAuth **`state`** (`sessions.byState`) |

`/oauth2/callback` fills `sess.Identity` on the session identified by `state`; the next poll resolves that
same session by cookie and sees it authenticated. So the cookie binds the browser that will be logged in,
and `state` (RFC 6749 §10.12 / RFC 9700) binds the out-of-band completion to it — and prevents a callback
from completing a session the user didn't initiate.

### Security properties

- `/oauth2/poll` only ever returns `{authenticated, return_to}` to the **cookie holder** — never tokens or
  identity claims; identity is exposed only via `/oauth2/userinfo` (claims, no raw tokens) to the
  authenticated session.
- `return_to` is validated as a local path (open-redirect guard) at `/oauth2/start`.
- `state` is single-use per login session and high-entropy; PKCE (`S256`) binds the code exchange.
- `sign_out` is CSRF-guarded with `X-Requested-With` in addition to `SameSite`.

## 4. Why `SameSite=Lax` (not Strict)

The login returns from the IdP cross-site (a top-level GET navigation). A `Strict` cookie is withheld on
that landing request, so the session would look absent and the forward_auth gate would loop. `Lax` sends the
cookie on top-level GET navigations while still blocking it on cross-site subrequests; state-changing
endpoints (`sign_out`) add the `X-Requested-With` check. This matches the **OWASP** and **RFC 6265bis**
guidance for session cookies in redirect-based login.

## References

- IETF `draft-ietf-oauth-browser-based-apps` — OAuth 2.0 for Browser-Based Applications (Token-Mediating Backend)
- RFC 6749 — OAuth 2.0 (auth-code flow, `state` §10.12)
- RFC 7636 — PKCE
- RFC 8628 — OAuth 2.0 Device Authorization Grant (QR + polling)
- OpenID Connect CIBA Core 1.0 — decoupled auth, poll/ping/push modes
- RFC 9700 — OAuth 2.0 Security Best Current Practice
- RFC 6265bis — HTTP cookies (`__Host-`, `SameSite`, `HttpOnly`, `Secure`)
- OWASP Session Management Cheat Sheet; OWASP ASVS v4 §V3 (Session Management)
- nginx `ngx_http_auth_request_module`; Caddy `forward_auth`; oauth2-proxy (`/oauth2/*`, `X-Auth-Request-*`)
- gematik: OpenID Federation (sectoral IDPs), IDP-Dienst + gematik Authenticator (`authenticator://` deep link)
