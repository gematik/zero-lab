---
id: TASK-98
title: 'Go: TLS server verification hooks for TI-PKI and hardened Web-PKI'
status: To Do
assignee: []
created_date: 2026-10-15 05:20
updated_date: '2026-11-05T19:31:00Z'
labels:
  - go
  - spec
  - keys
dependencies:
  - TASK-97
references:
  - docs/architecture.md
  - go/docs/design.md
priority: medium
ordinal: 96000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Go side of TASK-97. Go clients verify TLS servers with crypto/tls and the system roots: idpd, openid, oidf, epa (whose aggregators carry TI component certificates, so it skips verification today), and pep and pdp for their outbound calls.

go/tipki implements both profiles of spec/pki-validation natively with the standard library, as it does for certificates (held to ti-pki by the shared corpus). Each profile is a tls.Config constructor whose VerifyConnection does the whole verification, with the same immutable trust snapshot, atomic swap and bounded verdict cache as the Rust side. A caller cannot weaken a profile, and no client falls back to the system roots.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/tipki offers a tls.Config constructor per profile of spec/pki-validation, passing the shared corpus
- [ ] #2 Every Go client of a TI endpoint uses the TI-PKI profile and every client of an internet endpoint the hardened Web-PKI profile; epa no longer skips verification
- [ ] #3 Benchmarks with the same budget as TASK-97 for a cold and a cached verification
<!-- AC:END -->
