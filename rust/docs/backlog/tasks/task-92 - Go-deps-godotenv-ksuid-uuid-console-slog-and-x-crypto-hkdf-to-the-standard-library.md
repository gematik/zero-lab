---
id: TASK-92
title: >-
  Go deps: godotenv, ksuid, uuid, console-slog and x/crypto/hkdf to the standard
  library
status: In Progress
assignee: []
created_date: '2026-10-14 20:44'
updated_date: '2026-10-20 18:24'
labels:
  - go
  - deps
dependencies: []
references:
  - docs/conventions/dependencies.md
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
- [ ] #1 ksuid, google/uuid, console-slog and x/crypto/hkdf removed from every go.mod; godotenv stays (decision in the notes)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision (2026-10-20): godotenv stays. A .env holds paths to secrets or secret names, never secret values, so it does not conflict with secrets from files. Done on chore/go-stdlib-uuid: ksuid and github.com/google/uuid replaced by the standard library uuid (Go 1.27) as NewV4 everywhere (state, nonce, session IDs, jti, request IDs: unguessable, so not v7, which leaks the time and has 74 random bits); x/crypto/hkdf replaced by crypto/hkdf in epa (VSDM proof key, VAU K1/K2; old and new output compared byte for byte over 200 random inputs). bff, dpop, epa, pdp, pep, zaddy, go.work and their Dockerfiles at Go 1.27. Open: console-slog (dev console output of zero-epa and zero-pdp).
<!-- SECTION:NOTES:END -->
