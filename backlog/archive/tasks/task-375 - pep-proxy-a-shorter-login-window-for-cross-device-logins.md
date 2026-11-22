---
id: TASK-375
title: 'pep/proxy: a shorter login window for cross-device logins'
status: To Do
assignee: []
created_date: '2026-11-18T06:12:00Z'
updated_date: '2026-11-22 12:18'
labels:
  - pep-proxy
  - security
  - oauth
dependencies: []
priority: low
ordinal: 390000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A decoupled (OIDF QR) or authenticator (idpd) login cannot be bound to the browser that started it (TASK-364, go/pep/proxy/docs/DESIGN.md §3). Its state is good for LoginStateTTL, 15 minutes, which is the window of cross-device consent phishing (draft-ietf-oauth-cross-device-security). A shorter window for these modes, as short as the IdP's own login allows, narrows it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The state of a cross-device login expires after a configurable window shorter than LoginStateTTL, with a default chosen from the OIDF and idpd login times
- [ ] #2 A test named after draft-ietf-oauth-cross-device-security proves a late callback is refused
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: archived by the maintainer's decision.
<!-- SECTION:NOTES:END -->
