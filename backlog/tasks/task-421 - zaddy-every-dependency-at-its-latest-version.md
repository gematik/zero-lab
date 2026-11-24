---
id: TASK-421
title: 'zaddy: every dependency at its latest version'
status: In Progress
assignee: []
created_date: '2026-11-24T05:52:00Z'
updated_date: '2026-11-24T05:52:00Z'
labels:
  - go
  - zaddy
dependencies: []
ordinal: 434000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Bring go/zaddy's dependencies to their latest versions (go get -u ./... && go mod tidy), Caddy included, after TASK-418 lifted only OpenTelemetry. In-repo modules stay pinned by just sync.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go get -u leaves nothing to raise in go/zaddy
- [ ] #2 govulncheck, mod-check, lint and tests of go/zaddy are green
- [ ] #3 No new module enters go.mod's direct requirements
<!-- AC:END -->
