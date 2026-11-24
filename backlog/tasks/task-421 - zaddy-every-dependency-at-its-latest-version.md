---
id: TASK-421
title: 'zaddy: every dependency at its latest version'
status: Done
assignee: []
created_date: '2026-11-24T05:52:00Z'
updated_date: '2026-11-24T18:32:00Z'
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
- [x] #1 go get -u leaves nothing to raise in go/zaddy
- [x] #2 govulncheck, mod-check, lint and tests of go/zaddy are green
- [x] #3 No new module enters go.mod's direct requirements
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zaddy's dependencies at their latest versions that build with Caddy 2.11.9; quic-go v0.63.0 and go.step.sm/crypto v0.91.0 held back (Caddy 2.11.9 does not build with newer); go.work on Go 1.27.3 for nebula v1.12.0. Full Go check green, govulncheck clean.
<!-- SECTION:FINAL_SUMMARY:END -->
