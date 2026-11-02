---
id: TASK-190
title: 'gemidp: download trust material itself, for a standalone image'
status: In Progress
assignee: []
created_date: '2026-11-02T18:17:00Z'
updated_date: '2026-11-02T18:35:00Z'
labels:
  - go
  - gemidp
  - security
dependencies: []
priority: high
ordinal: 200000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A standalone image cannot mount a bundle from a producer. Add a native trust source to go/gemidp that fetches roots.json, the TSL, its detached signature and the signer's OCSP from the fixed gematik hosts and verifies them with go/tipki. The bundle file stays for air-gapped sites.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A client configured to fetch starts with no mounted file, and refuses to start when the material cannot be had or does not verify
- [x] #2 Refresh runs in the background and never on a login; certificates are refused once the copy in memory is too old
- [x] #3 The list in use is the one the HTTPS host's hash names, so an older list served over plain HTTP is refused; requirement-named tests
- [x] #4 servers.md allows both sources, recorded in a decision; HITL against the reference environment
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Built: FetchingTrust, IDPV-007 and 008, decision-12. Live with nothing mounted via just gemidp-trust-fetch-test; zero-pep-proxy binary started with nothing mounted. AC 4 waits on the maintainer's HITL.

2026-11-02: HITL with the image passed, confirmed by the maintainer.
<!-- SECTION:NOTES:END -->
