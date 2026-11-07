---
id: TASK-259
title: OAuth clients and servers checked against RFC 9700 (OAuth 2.0 Security BCP)
status: To Do
assignee: []
created_date: '2026-11-07T18:04:00Z'
labels:
  - security
  - spec
  - go
  - rust
dependencies: []
references:
  - https://www.rfc-editor.org/rfc/rfc9700
  - docs/design/servers.md
priority: medium
type: task
ordinal: 275000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 9700 (January 2025) is the OAuth 2.0 Security Best Current Practice: PKCE for every client, no implicit and no resource-owner password grant, exact redirect URI matching, sender-constrained or rotated refresh tokens, audience-restricted access tokens, mix-up defence, no open redirectors, among others. The repo has OAuth/OIDC clients and servers (rust ti-idpd and ti-directory, go idpd, openid, oidf, pdp authorization server, pep proxy), and none is traced against it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each RFC 9700 §2 and §4 requirement that applies to a client or server here is listed per component with the code or test that meets it, or recorded as not applicable with the reason
- [ ] #2 each gap becomes its own task
<!-- AC:END -->
