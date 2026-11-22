---
id: TASK-372
title: >-
  idpd Authenticator: the challenge comes only from the IDP-Dienst (related
  finding, parity with Rust)
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-22 15:14'
labels:
  - idpd
  - security
dependencies: []
priority: low
ordinal: 387000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`Authenticator.Authenticate` (`go/idpd/authenticator.go:158-179`) GETs whatever authorization URL it is handed, for zero-epa the Aktensystem's `Location`, and only then checks the challenge's IDP signature. ti-directory-client refuses an authorization URL outside its IDP's origin before anything is fetched or signed (`owner.rs` `to_own_idp`). RFC 9700 has no rule for the Authenticator's role. This is outside the RFC and listed for parity. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The authorization URL must have the origin of the IDP-Dienst's `authorization_endpoint` from its signed metadata, or nothing is fetched. Test named after the requirement, and the same rule in ti-idpd-client if it lacks it.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, maintainer: to be built later, in the Rust sprint (parity with ti-directory-client).
<!-- SECTION:NOTES:END -->
