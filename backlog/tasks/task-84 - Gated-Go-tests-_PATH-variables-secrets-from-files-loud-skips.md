---
id: TASK-84
title: 'Gated Go tests: _PATH variables, secrets from files, loud skips'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - tests
dependencies: []
references:
  - docs/design/testing.md
priority: medium
ordinal: 82000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GEMIDP_SMCB_P12 and EPA_SMCB_P12 hold paths without _PATH; VSDM_HMAC_KEY carries a secret as its value; not every skip says what the test proves.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 variables renamed with _PATH, VSDM_HMAC_KEY read from a file, every skip names its variable and what it proves
<!-- AC:END -->
