---
id: TASK-98
title: 'Go: TLS server verification hooks for TI-PKI and hardened Web-PKI'
status: Done
assignee: []
created_date: 2026-10-15 05:20
updated_date: '2026-11-06T18:25:00Z'
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
- [x] #1 go/tipki offers a tls.Config constructor per profile of spec/pki-validation, passing the shared corpus
- [x] #2 Every Go client of a TI endpoint uses the TI-PKI profile and every client of an internet endpoint the hardened Web-PKI profile; epa no longer skips verification
- [x] #3 Benchmarks with the same budget as TASK-97 for a cold and a cached verification
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged ff908674. go/tipki: the ti profile's TLS server check (spec/pki-validation corpus, 23 ti cases). go/tipki/titls: web profile (27 cases), tls.Config per profile, swapped ti snapshot, bounded verdict cache, revocation fetcher, NewWebHTTPClient; deviations of crypto/tls listed in CONFORMANCE.md; just tls-bench within 5 ms cold / 10 µs cached. go/tipki/fetch: TSL download and refresh for prod/ref/test/dev, the ti snapshot withdrawn when stale; idpd on it. Clients: epa requires a TLS config (no InsecureSkipVerify, TASK-229 closed), zero-epa verifies the Aktensysteme under ti over its own TSL; idpd takes the host's client as a constructor parameter; zero-pdp and zero-pep-proxy hand web clients to idpd, openid, oidf and the PDP backend. Gated suites passed live (maintainer). Follow-ups: TASK-233, 234, 236.
<!-- SECTION:FINAL_SUMMARY:END -->
