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
or idpd via the gematik Authenticator app — the originating browser cannot follow a single redirect chain.
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
| **completion** (`/oauth2/callback?code&state`) | the 2nd device (OIDF QR) or the Authenticator app (idpd) | the OAuth **`state`** (`sessions.byState`) |

`/oauth2/callback` fills `sess.Identity` on the session identified by `state`; the next poll resolves that
same session by cookie and sees it authenticated. So the cookie binds the browser that will be logged in,
and `state` (RFC 6749 §10.12 / RFC 9700) binds the out-of-band completion to it.

### Who may complete a login

`/oauth2/start` records the login's mode on the session (`login_mode`), and the callback applies its rule
before it redeems the code:

- **redirect** (plain OIDC, and the PDP backend for providers that are not OIDF): the callback must carry the
  cookie of the session its `state` names (RFC 9700 §2.1.1). Without it, the session and its `state` are
  removed and the code is never redeemed, so a victim lured to an authorization URL another browser started
  cannot sign that browser in. A session stored without a mode gets this rule.
- **decoupled** (OIDF QR) and **authenticator** (idpd): the login completes on a second device or in the app
  the deep link opened, which hold no cookie by design. The `state` alone names the session.

### Cross-device risk that remains

A cross-device login cannot be bound to the browser that started it, so the attack the cookie check stops
for redirect logins stays possible in principle (draft-ietf-oauth-cross-device-security, "cross-device
consent phishing"): an attacker starts a login, hands a victim the QR code or the deep link, and if the
victim confirms it, the attacker's browser holds a session with the victim's identity. In force against it:

- the `state` index lives for `LoginStateTTL` (15 minutes) and is used once, so a started login is good for
  one completion within that window;
- nothing completes without the victim confirming the login on their own device, at the identity provider
  or in the gematik Authenticator;
- only the cookie holder learns the outcome (`/oauth2/poll`), and the session id is rotated there.

pep cannot detect that the person who confirms is not the person who started; the remaining defence is that
user's attention. A shorter window for cross-device logins would narrow it further.

### Mix-up: a gap accepted for now

All providers answer at one `/oauth2/callback`, and the callback does not learn which authorization server
sent the code: none of the TI's providers sends the `iss` of RFC 9207 or announces
`authorization_response_iss_parameter_supported` (the IDP-Dienst, TK, RISE and BITMARCK federation IdPs, as of
November 2026), and no gematik specification asks for it. RFC 9700 Section 2.1 requires a mix-up defence for a
client of several authorization servers, by `iss` or by a redirect URI per issuer. Neither is built (maintainer,
2026-11-22). In force against it: a callback redeems its code only at the token endpoint of the provider the
session's `state` names, never one the response chooses; federation providers are admitted only from the
master's signed IdP list, so an attacker's server has to be a federation member; and the ID token's `iss` must
be that provider.

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

## 5. Stateless validation on the hot path (planned)

§2 currently resolves the session with a `kv` read **per request**. For horizontally-scaled deployments with
an instant-revocation requirement this is being replaced by a signed **session-snapshot cookie** (verified
locally on `/oauth2/auth`, no `kv`) plus an in-memory **revoked-session set** synced over a `kv` pub/sub bus
(with a durable backstop) for fleet-wide instant revocation — the "cookie caching" / hybrid-session pattern.
`kv` then sees ~one read per snapshot-TTL per session instead of one per request. Decision + plan:
[`docs/stateless-session-validation.md`](docs/stateless-session-validation.md).

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
