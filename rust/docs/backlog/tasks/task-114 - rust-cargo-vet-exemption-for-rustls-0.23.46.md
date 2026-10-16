---
id: TASK-114
title: 'rust: cargo vet exemption for rustls 0.23.46'
status: To Do
assignee: []
created_date: '2026-10-16 05:38'
labels:
  - rust
  - supply-chain
dependencies: []
priority: low
ordinal: 120000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cargo.lock has rustls 0.23.46 while supply-chain/config.toml exempts 0.23.45, so just vet (tier 2, before tagging) fails. Found during TASK-103.4; not caused by it. Audit or record the new version.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just vet passes
<!-- AC:END -->
