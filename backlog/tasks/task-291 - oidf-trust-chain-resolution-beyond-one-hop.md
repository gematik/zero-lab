---
id: TASK-291
title: 'oidf: trust chain resolution beyond one hop'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 307000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FetchEntityStatement (go/oidf/oidf.go) verifies a fixed chain: the federation master's statement against a configured key, its statement about the subject, the subject's own. authority_hints are not walked, there are no intermediates, no choice among trust anchors, and no expiry of the chain as the earliest exp of its statements. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A chain through an intermediate resolves and is refused when any statement is invalid or expired; the chain reports when it expires
<!-- AC:END -->
