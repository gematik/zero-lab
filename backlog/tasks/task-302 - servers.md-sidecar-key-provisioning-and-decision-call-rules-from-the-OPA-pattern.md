---
id: TASK-302
title: >-
  servers.md: sidecar, key-provisioning and decision-call rules from the OPA
  pattern
status: Done
assignee: []
created_date: '2026-11-12T21:17:00Z'
updated_date: '2026-11-14T16:18:00Z'
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
- [x] #1 Rule 27 committed as its own change
- [x] #2 Accepted items edited into rules 6, 7, 8, 16, 17, 21, 26; no rule renumbered
- [x] #3 decision-16 (workload TLS keys inside, certificate after attestation) and decision-17 (third-party sidecars rebuilt reproducibly) recorded and linked
- [x] #4 Rule count in CLAUDE.md and docs/README.md correct; TASK-169 notes the consequences for OPA
- [x] #5 Cited rule numbers still point to the same content; links resolve
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-169 (OPA) no longer exists (removed in the backlog review 60fd9cce) and is not recreated; the OPA consequences live in rules 6, 7, 8, 16, 21, 26 and decision-16/17, and the Go profile maps the decision call. CoCo check (item 1): medium: Memory is a tmpfs in the confidential guest's memory, host-forwarded volumes are not automatically confidential (secondary source, so the rule says no more than that). Rule count: CLAUDE.md 27, principles.md lists rule 27. Go just check not run: docs only, no code.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
servers.md takes the rules from the OPA container pattern that fit confidential workloads, in place so rule numbers stay: rule 6 (TLS key generated inside, certificate after attestation, decision-16; rotation covers sidecars), rule 7 (image vulnerability scan in CI; third-party sidecars rebuilt reproducibly, decision-17), rule 8 (socket in a memory-backed emptyDir; a sidecar serves only its client's operations and none that change its configuration; policy engines only as sidecars; mesh mTLS only as defence in depth), rule 16 (decision calls deny on transport error, timeout, non-success or undefined result), rule 17 (no address, mode or trust source in the image; inconsistent combinations refused), rule 21 (policy hash in the audit record, engine decision log off), rule 26 (socket negative tests). Rule 27 (any UID, OpenShift) included. Rejected: plaintext behind a mesh, remote policy services, bundle polling, fixed UIDs, open diagnostic ports. Docs only; links checked.
<!-- SECTION:FINAL_SUMMARY:END -->
