---
id: TASK-211
title: 'ti-cli: connector get status colors a condition by its severity'
status: In Progress
assignee: []
created_date: '2026-11-04T13:23:00Z'
updated_date: '2026-11-04T13:24:00Z'
labels:
  - ti-cli
  - cli
dependencies: []
priority: low
ordinal: 218000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`connector get status` shows every active error condition in red, also those of severity Info, which gemSpec_Kon TAB_KON_503 uses for conditions such as EC_TLS_Client_Certificate_Security: an Info condition reads like a fault. Found on a secunet Konnektor with two Info conditions and both VPNs online.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A condition of severity Info is not colored
- [x] #2 A condition of severity Warning is shown as a warning
- [x] #3 A condition of any other severity, also an unknown one, stays red
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On refactor/ti-cli-plain-files with the next ti version.
<!-- SECTION:NOTES:END -->
