---
id: TASK-393
title: >-
  servers.md rule 31: every container's health is probed, and startup, readiness
  and liveness mean different things
status: Done
assignee: []
created_date: '2026-11-19 13:42'
updated_date: '2026-11-22 11:08'
labels:
  - docs
  - servers
  - kubernetes
dependencies: []
references:
  - docs/design/servers.md
priority: medium
ordinal: 406000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The rules say only that liveness and readiness reflect real state (rule 8) and that health endpoints sit on the admin listener with mTLS (rule 23), which a kubelet's probe cannot present. Nothing says that a sidecar needs probes, how a container that listens only on a Unix socket is probed, or that liveness must not depend on a dependency. Found with the HSM proxy sidecar (TASK-389), whose hsm-proxy health ready|live are exec probes. Documentation only; the servers are checked against the rule in a task of their own.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 servers.md has rule 31: probes for every container, main and sidecar; what startup, readiness and liveness each answer; how a container with a network listener and one with only a Unix socket is probed; health read from state kept by a background check; the health state as a metric and a log line; how it is tested
- [x] #2 Rule 8 and rule 23 refer to rule 31 instead of saying it in part, and rule 23's probe path is consistent with the kubelet, which presents no client certificate
- [x] #3 CLAUDE.md counts 31 rules
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: rule 31 written; rule 8 points to it for probes and native sidecar ordering, rule 23 allows the bare probe path without a client certificate. The servers are checked in TASK-394. docs/principles.md item 10 lists the rules only up to 27 (28 to 30 were not added either); left as it is.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
servers.md rule 31: probes for every container, sidecars included; startup, readiness and liveness each answer their own question; health read from a background check's state; exec probes for a Unix-socket sidecar, grpc.health.v1 or a health path on the admin listener otherwise; the health change as a log line and a metric; tests named. Rules 8 and 23 refer to it; CLAUDE.md counts 31 rules. Checking the servers against it is TASK-394; the metrics' detail waits for the observability specification (DRAFT-1).
<!-- SECTION:FINAL_SUMMARY:END -->
