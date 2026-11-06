---
id: TASK-97.1
title: 'TLS verification (a): spec/pki-validation with the ti and web profiles'
status: In Progress
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T07:48:00Z'
labels:
  - spec
  - ti-pki
  - security
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 235000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (a): the shared specification both implementations are held to.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 spec/pki-validation/README.md: scope, references, profiles ti and web, rules with IDs, result codes, algorithm, requirement mapping, security considerations
- [x] #2 CONFORMANCE.md and a generated TEST-ONLY corpus with a positive case and a negative case per rule, listed in manifest.json
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/pki-validation (../zero-lab-tls): README (TLSV-001 to 051, maintainer: system roots for web, SAN and CN for ti, wildcards for both), CONFORMANCE, testdata: generate.sh (OpenSSL 4.1.0, keys never written), 35 certificates, 27 OCSP responses (verified with openssl ocsp), 2 CRLs, manifest.py -> 50 cases, handshake.json. TLSV-002, 014, 050, 051 are proved by implementation tests (CONFORMANCE). No implementation runs the corpus yet: that is 97.2.
<!-- SECTION:NOTES:END -->
