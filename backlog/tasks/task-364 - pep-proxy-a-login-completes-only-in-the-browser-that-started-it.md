---
id: TASK-364
title: 'pep/proxy: a login completes only in the browser that started it'
status: Done
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-22 11:34'
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
- [x] #1 In redirect mode a callback without the cookie of the session its `state` names is refused before the code is redeemed, and the state is consumed. Test named after RFC 9700 §2.1.1.
- [x] #2 The login mode is recorded on the session at `/oauth2/start`, so the callback knows which rule applies. Decoupled and authenticator modes keep working (e2e).
- [x] #3 The remaining cross-device risk of decoupled and authenticator logins is written down in the pep/proxy docs, with the mitigations in force.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Branch fix/rfc9700-gaps, commit 944a3110. Session.LoginMode (login_mode) is set from LoginStart.Mode at /oauth2/start. handleCallback: when the request does not own the session and the mode is not decoupled/authenticator, the session and its state are removed before Complete, and invalid_state is rendered; an empty mode (sessions stored before) gets the redirect rule. Tests: TestRFC9700_2_1_1_ARedirectLoginCompletesOnlyInTheBrowserThatStartedIt (no cookie, another cookie, then the starter is refused too; fails without the check), TestRFC9700_2_1_1_ACrossDeviceLoginCompletesWithoutTheCookie (decoupled, authenticator: callback 200 and poll 200). docs/DESIGN.md §3: who may complete a login, and the cross-device risk that remains with the mitigations in force. AC #2: unit-tested; the e2e of the OIDF QR and idpd logins is the maintainer's HITL. Rollout: zero-pep-proxy refuses unknown session members, so an older instance cannot read a session a newer one wrote; mixed versions only during a rolling update.

2026-11-22: e2e decoupled passed on zerobin with spilikin/zero-pep-proxy:0.5.1-dev.aa2d9929 (main aa2d9929, fix included): Techniker Krankenkasse RU2 (https://idbroker.tk.ru2.nonprod-ehealth-id.de), login start mode=decoupled at 11:20:16, login complete decoupled=true at 11:21:01, the starting browser signed in (maintainer). Authenticator mode (idpd) not yet run e2e.

2026-11-22: e2e authenticator passed on zerobin, same image: gematik IDP-Dienst (https://idp-ref.app.ti-dienste.de) through the gematik Authenticator and the TI-Gateway, login start mode=authenticator at 11:32:51, login complete decoupled=true at 11:33:06 (maintainer).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
A redirect login completes only in the browser that started it (RFC 9700 §2.1.1): Session.LoginMode is recorded at /oauth2/start, and a callback without the cookie of the session its state names is refused before the code is redeemed, the session and its state removed. Decoupled (OIDF) and authenticator (idpd) logins are cross-device and complete without the cookie; their remaining risk and the mitigations in force are in docs/DESIGN.md §3. Tests: TestRFC9700_2_1_1_ARedirectLoginCompletesOnlyInTheBrowserThatStartedIt, TestRFC9700_2_1_1_ACrossDeviceLoginCompletesWithoutTheCookie. e2e on zerobin with 0.5.1-dev.aa2d9929: TK RU2 (decoupled) and the gematik IDP-Dienst via Authenticator and TI-Gateway. Fix in 944a3110 on main; not yet in a pep/proxy release (latest v0.5.1).
<!-- SECTION:FINAL_SUMMARY:END -->
