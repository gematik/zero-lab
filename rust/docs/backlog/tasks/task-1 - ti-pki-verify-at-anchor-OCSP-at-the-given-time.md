---
id: TASK-1
title: 'ti pki verify --at: anchor OCSP at the given time'
status: To Do
assignee: []
created_date: '2026-10-09 13:54'
labels:
  - ti-cli
  - ti-pki
  - ocsp
dependencies: []
references:
  - ti-cli/src/commands/verify.rs
priority: medium
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
With --at, path validation runs at the given instant, but the OCSP request and the response's validity window are still judged against the current time, so a historical check mixes two instants. Source: Obsidian note C_12791 (follow-ups).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti pki verify --at T judges OCSP thisUpdate/nextUpdate against T
- [ ] #2 the report says when OCSP was answered for an instant other than now, or that it could not be
<!-- AC:END -->
