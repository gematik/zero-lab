---
id: TASK-268
title: 'ti-idpd-client: the version at its first release'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T09:33:00Z'
labels:
  - rust
  - release
dependencies: []
ordinal: 284000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-idpd was published as 0.1.0; TASK-246 renamed it to ti-idpd-client. Decide at its first release whether it starts at 0.1.0 under the new name and what happens to the old crate on crates.io (a final release pointing to the new name, or yank).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the first release of ti-idpd-client follows a recorded decision
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision (maintainer, 2026-11-08): ti-idpd-client's first release is 0.2.0, following ti-idpd 0.1.0. just release ti-idpd-client=0.2.0 sets it at the release.
<!-- SECTION:NOTES:END -->
