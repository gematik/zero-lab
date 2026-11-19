---
id: TASK-399
title: >-
  servers.md: inside the cluster, own TLS/mTLS or plaintext with a declared
  mesh; target a mesh proxy inside the enclave
status: In Progress
assignee: []
created_date: '2026-11-19 15:19'
updated_date: '2026-11-19 15:20'
labels:
  - docs
  - servers
  - transport
dependencies: []
references:
  - docs/design/servers.md
  - docs/conventions/naming-and-config.md
priority: medium
ordinal: 412000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer, 2026-11-19: on a Unix socket inside the pod the sidecar does not ask who calls, and the keys it serves are configured. A connection inside the cluster, outside the pod, is one of two: 'manual' TLS/mTLS, which the workload terminates itself from files (rule 29), or the http:// opt-out with the deployment's own mesh providing mTLS. Today any declared mesh is allowed, wherever its proxy runs; the target is a mesh proxy inside the enclave, in the pod and measured with it (rule 7), so that TLS ends inside the TCB (rule 5). Rules 5, 8 and 17 forbid the mesh opt-out today ('never a workload's channel protection', 'plaintext to a peer outside the pod' refused) and are aligned. Documentation only; the HSM proxy's TCP listener is a task of its own.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Rule 29 says that a listener or peer inside the cluster is own TLS/mTLS or http:// with a declared mesh, that plaintext without a declared mesh is refused at start, and that the mesh is reported; it names the target, a mesh proxy inside the enclave
- [x] #2 Rules 5, 8 and 17 refer to rule 29 for the mesh opt-out instead of forbidding it
- [x] #3 naming-and-config.md has the suffix that declares the mesh
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: rule 29 has 'Inside the cluster, one of two' (own TLS/mTLS, or http:// with a declared mesh via …_MESH, refused without it, reported; now wherever the mesh proxy runs, target inside the enclave); rule 5 points to it, rule 8's mesh sentence allows it as channel protection where declared, rule 17 refuses plaintext outside the pod only without a declared mesh; naming-and-config.md has the …_MESH suffix. Follow-ups: TASK-400 (the target), TASK-401 (hsm-proxy's TCP listener).
<!-- SECTION:NOTES:END -->
