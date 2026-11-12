---
id: TASK-302
title: >-
  servers.md: sidecar, key-provisioning and decision-call rules from the OPA
  pattern
status: To Do
assignee: []
created_date: '2026-11-12T21:17:00Z'
labels:
  - docs
dependencies: []
ordinal: 318000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The maintainer's 'Secure container image pattern: app with OPA policy decisions' (2026-11-12), evaluated item by item against the confidential-workload rules (plan /Users/serg/.claude/plans/cheerful-tickling-bear.md). Accepted items go into the existing rules, without renumbering: rule 6 (TLS key generated inside the workload, certificate after attestation; rotation covers sidecars), 7 (third-party sidecars rebuilt reproducibly; image vulnerability scan), 8 (memory-backed socket volume, no configuration-changing API, policy engines only as sidecars, mesh mTLS only defence in depth), 16 (decision-call outcomes that deny), 17 (runtime contract and refused combinations), 21 (policy hash in the decision's audit record, engine decision log off), 26 (negative tests). Rejected: mesh plaintext, remote policy service, bundle polling, fixed UIDs, diagnostic port on 0.0.0.0. Also commits the pending rule 27 (any UID, OpenShift).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Rule 27 committed as its own change
- [ ] #2 Accepted items edited into rules 6, 7, 8, 16, 17, 21, 26; no rule renumbered
- [ ] #3 decision-16 (workload TLS keys inside, certificate after attestation) and decision-17 (third-party sidecars rebuilt reproducibly) recorded and linked
- [ ] #4 Rule count in CLAUDE.md and docs/README.md correct; TASK-169 notes the consequences for OPA
- [ ] #5 Cited rule numbers still point to the same content; links resolve
<!-- AC:END -->
