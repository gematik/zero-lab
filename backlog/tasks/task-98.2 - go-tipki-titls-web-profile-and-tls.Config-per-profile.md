---
id: TASK-98.2
title: 'go/tipki/titls: web profile and tls.Config per profile'
status: Done
assignee: []
created_date: '2026-11-06T14:01:00Z'
updated_date: '2026-11-06T18:25:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 245000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
web profile (system roots plus the TLSV web rules: keys, signatures, name, validity, OCSP or CRL) and a tls.Config constructor per profile with versions, suites and curves of handshake.json; bounded verdict cache (TLSV-050) and an atomically swapped trust snapshot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the web corpus cases pass
- [x] #2 the configs follow handshake.json and a caller cannot weaken them
- [x] #3 the verdict cache is bounded and the ti snapshot swaps atomically, with tests
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
339b718d on spec/go-pki-validation: go/tipki/titls (WebCheck, Fetcher/HTTP/Offline, TrustSource with atomic swap, TiVerifier/WebVerifier and ClientConfig, bounded verdict cache, fuzz target FuzzWebCheck); 27 web + 23 ti corpus cases pass. Go's crypto/tls cannot narrow the offer fully (ChaCha20 in TLS 1.3, client signature schemes, no brainpool, IP hosts): listed in spec/pki-validation/CONFORMANCE.md. Reuse stops at nextUpdate too (TLSV-050); Rust's ti-tls does not: added to TASK-232. tipki.OCSPChecker caches without a bound: TASK-234.
<!-- SECTION:NOTES:END -->
