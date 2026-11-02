---
id: TASK-177
title: 'gemidp: token key and code verifier written to the log at Info'
status: Done
assignee: []
created_date: '2026-11-02T06:16:00Z'
updated_date: '2026-11-02T23:09:00Z'
labels:
  - go
  - gemidp
  - security
  - bug
dependencies: []
priority: high
ordinal: 187000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/gemidp/client.go logs tokenKeyPayload with slog.Info: the token key that decrypts the IDP's tokens, and the PKCE code verifier. Found while reading gemidp for TASK-171. Secrets do not go to logs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 neither value reaches a log at any level; a test proves it
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed with requirement-named tests in the consolidation.
<!-- SECTION:FINAL_SUMMARY:END -->
