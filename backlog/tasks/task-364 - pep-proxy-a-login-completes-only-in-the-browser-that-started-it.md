---
id: TASK-364
title: 'pep/proxy: a login completes only in the browser that started it'
status: In Progress
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-18T06:05:00Z'
labels:
  - pep-proxy
  - security
  - oauth
dependencies: []
priority: high
ordinal: 379000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`handleCallback` (`go/pep/proxy/proxy.go:440-494`) resolves the session by `state` and calls `backend.Complete` (`proxy.go:457`) before it checks that the request carries the session's cookie (`requestOwnsSession`, `proxy.go:477`). That check only chooses between redirecting and rendering `complete.html`. In redirect mode (plain OIDC, and the PDP backend for non-OIDF providers, `backend_provider.go:111-117`, `backend_pdp.go:441-447`), an attacker can start a login, keep the cookie, and lure a victim to the IdP authorization URL. With an IdP SSO session no interaction is needed. The victim's callback then authenticates the attacker's session with the victim's identity. RFC 9700 §2.1.1 requires the PKCE challenge or nonce to be bound to the user agent that started the transaction. Here it is bound only to a server-side session that any browser can complete. Decoupled (OIDF QR) and authenticator (idpd) modes are cross-device by design. They need the cross-device mitigations instead (short lifetime, the user sees what they confirm, draft-ietf-oauth-cross-device-security), not the cookie check. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 In redirect mode a callback without the cookie of the session its `state` names is refused before the code is redeemed, and the state is consumed. Test named after RFC 9700 §2.1.1.
- [ ] #2 The login mode is recorded on the session at `/oauth2/start`, so the callback knows which rule applies. Decoupled and authenticator modes keep working (e2e).
- [ ] #3 The remaining cross-device risk of decoupled and authenticator logins is written down in the pep/proxy docs, with the mitigations in force.
<!-- AC:END -->
