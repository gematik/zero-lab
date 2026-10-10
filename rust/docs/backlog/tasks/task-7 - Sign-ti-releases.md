---
id: TASK-7
title: Sign ti releases
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - release
dependencies: []
references:
  - Justfile
  - docs/development.md
priority: low
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SHA256SUMS of ti releases is unsigned (Known compromises in docs/development.md; the user deferred signing). Planned: minisign key via rsign2, secret at TI_RELEASE_KEY_PATH, public key in ti-cli/minisign.pub; just release signs SHA256SUMS, publish-brew verifies it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just release writes SHA256SUMS.minisig; publish-brew refuses an unverified SHA256SUMS
- [ ] #2 the Known compromises row is removed
<!-- AC:END -->
