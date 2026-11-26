---
id: TASK-436
title: 'ti-pki: spike – gematik''s PKI test suite as a conformance test, Docker only'
status: To Do
assignee: []
created_date: '2026-11-24 10:09'
updated_date: '2026-11-26 12:35'
labels:
  - ti-pki
  - tests
dependencies: []
references:
  - docs/design/testing.md
  - spec/tsl-detached/README.md
  - spec/pki-validation
  - 'https://github.com/gematik/app-PkiTestsuite'
priority: medium
type: spike
ordinal: 434000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Find out whether, and how far, gematik's app-PkiTestsuite (https://github.com/gematik/app-PkiTestsuite, 8.1.0) can serve as an external conformance check of TUC_PKI_001/018/006 in zero-lab. The suite runs in containers only: no Maven build, no Java on the host. gematik publishes no images (Docker Hub gematik1 and GHCR checked), only the release zip pkits-distro-assembly-8.1.0.zip (sha256 0cfadd8446d689faa62291b995d982dbdad2f01a26f0f218eccb2ce59404c031); the image is built from it. Known obstacles: the suite serves XMLDSig TSLs without .sig/.ocsp (spec/tsl-detached, TASK-166); zero-lab has no server that validates TI client certificates with the core; OCSP goes to the AIA URL, not the TSL's ServiceSupplyPoint. Scope: Docker setup, a baseline against gematik's SUT simulator, an attempt in script mode with ti pki verify without changing ti-pki, a compatibility matrix, follow-up tasks.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The suite runs with docker compose against gematik's SUT simulator, with no Java or Maven on the host
- [ ] #2 A compatibility matrix (test class/method, requirement, status, reason) exists as a backlog doc
- [ ] #3 The result of the script-mode attempt with ti pki verify is recorded
- [ ] #4 Every gap found has its own follow-up task
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26: parked until gematik releases an updated PKI test suite (AIA of the internet certificates pointing at the suite's responder, /ocsp/internet; .sig next to the TSL). Work so far is on branch spike/pkits (doc-8, Dockerfile, compose); the suite changes are prepared in gematik's repository, not merged.
<!-- SECTION:NOTES:END -->
