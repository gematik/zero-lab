---
id: TASK-312
title: 'pdp: authzserver.NewFromConfigFile cannot succeed'
status: In Progress
assignee: []
created_date: '2026-11-14T15:21:00Z'
updated_date: '2026-11-15T09:10:00Z'
labels: []
dependencies: []
ordinal: 327000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
authzserver.NewFromConfigFile (go/pdp/authzserver/server.go) builds a Config from YAML, but the signing key and, since TASK-306, the stores are yaml:"-", so New always refuses it. Remove it, or make it take the parts YAML cannot carry. Found by the review of refactor/module-stores.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 NewFromConfigFile is removed or works, with a test if kept
<!-- AC:END -->
