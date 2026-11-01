---
id: TASK-171
title: >-
  gemidp: verify the IDP-Dienst certificate against the TSL (Go relying-party
  side)
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - gemidp
  - security
dependencies: []
priority: high
ordinal: 181000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/gemidp takes the IDP-Dienst's signing key from the x5c of the discovery document and verifies the discovery document, challenge and id_token with it (shared.go:155-193), but never verifies that certificate: shared.go:142 logs 'Certificate of discovery document not verified. Don't trust it in production.' The Rust side does it (TASK-27, done, ti-idpd checks the IDP certificates against the TSL). The servers that use gemidp as relying party (pdp, pep, bff) therefore trust whatever the discovery endpoint presents. Per decision-10 the check goes through the stateless ti-pki-helper (TASK-120.4, TASK-120.6) with the IDP profile, not through a Go implementation. Rules: docs/architecture.md trust from verification only; docs/design/servers.md 16.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the discovery document's certificate is verified against the TSL with the IDP-Dienst profile and OCSP before its key is used; a failed verdict is a hard error, never a warning
- [ ] #2 requirement-named tests with the spec corpus and a fake helper; the warning log line is gone
<!-- AC:END -->
