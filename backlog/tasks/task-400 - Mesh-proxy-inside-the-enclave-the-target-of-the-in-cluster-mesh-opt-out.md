---
id: TASK-400
title: 'Mesh proxy inside the enclave: the target of the in-cluster mesh opt-out'
status: To Do
assignee: []
created_date: '2026-11-19 15:20'
labels:
  - servers
  - transport
  - kubernetes
dependencies:
  - TASK-399
references:
  - docs/design/servers.md
priority: low
ordinal: 413000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 29 (TASK-399) allows http:// inside the cluster with a declared mesh wherever its proxy runs, as the state for now. The target is a mesh proxy inside the enclave, in the pod and measured with it (rule 7), so that the channel ends inside the TCB (rule 5). To find out: which meshes can run their proxy as a native sidecar in a confidential pod and have its image in the pod policy that attestation measures (Istio ambient vs sidecar mode, Linkerd), what the deployments here use, and when the rule can drop 'wherever its proxy runs'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 For each mesh a deployment here uses, it is recorded whether and how its proxy runs inside the enclave and is measured
- [ ] #2 Rule 29 drops the transitional allowance, or records why it stays
<!-- AC:END -->
