---
id: TASK-98
title: 'Go: TLS server verification hooks for TI-PKI and hardened Web-PKI'
status: In Progress
assignee: []
created_date: 2026-10-15 05:20
updated_date: '2026-11-06T14:01:00Z'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Maintainer 2026-11-06: profiles in a subpackage of tipki; zero-epa downloads the TSL itself; all subtasks on one branch (spec/go-pki-validation).
98.1 ti server check in go/tipki, ti corpus cases of spec/pki-validation.
98.2 go/tipki/titls: web profile, tls.Config per profile (handshake.json), bounded verdict cache, atomic snapshot swap; web corpus cases.
98.3 benchmarks with TASK-97's budgets, just recipe.
98.4 go/tipki/fetch: idpd's FetchingTrust generalised (all envs incl. dev), used by idpd and epa as the ti snapshot source.
98.5 every Go client on its profile: epa proxy and probe ti (TASK-229), internet clients web; inventory first.
No new dependencies: standard library only. The ti tls.Config needs one InsecureSkipVerify (crypto/x509 refuses the TI's brainpool CAs) with a justified nolint, inside titls only, VerifyConnection doing the whole check.
<!-- SECTION:PLAN:END -->
