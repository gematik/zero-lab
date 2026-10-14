---
id: TASK-92
title: >-
  Go deps: godotenv, ksuid, uuid, console-slog and x/crypto/hkdf to the standard
  library
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - deps
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 90000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Small dependencies the standard library replaces: crypto/rand.Text for ksuid and uuid, slog for console-slog, crypto/hkdf for x/crypto/hkdf; godotenv conflicts with secrets from files.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the five modules removed from every go.mod
<!-- AC:END -->
