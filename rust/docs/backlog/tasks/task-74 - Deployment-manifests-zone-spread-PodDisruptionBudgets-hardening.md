---
id: TASK-74
title: 'Deployment manifests: zone spread, PodDisruptionBudgets, hardening'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - k8s
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 72000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The servers have no manifests; metsubushi/k8s.yaml has no topology spread or PDB (server rules 8, 13).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 manifests per server with non-root, read-only root filesystem, seccomp, probes, topology spread over three zones and PDBs
<!-- AC:END -->
