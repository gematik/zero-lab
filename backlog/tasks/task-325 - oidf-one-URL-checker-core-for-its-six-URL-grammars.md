---
id: TASK-325
title: 'oidf: one URL checker core for its six URL grammars'
status: In Progress
assignee: []
created_date: '2026-11-15T08:28:00Z'
updated_date: '2026-11-15T09:53:00Z'
labels:
  - oidf
  - go
dependencies: []
ordinal: 340000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
oidf has checkFederationURL, checkEntityIdentifier, checkRegisteredRedirectURI, checkRequestURI and entityIDOfStatementURI, openid has requireHTTPS; they share an https / printable ASCII / no user info core that could be one helper with the per-use rules on top, so a fix lands in one place. Found by the final review of feat/oidf-rp (TASK-315).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One shared core; each grammar adds only its own rules; existing tests and fuzz targets unchanged in what they prove
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-15: openid's requireHTTPS stays in openid: it has a different grammar (case-insensitive scheme, no user-info rule) and lives in another package; sharing the core would change behaviour. The acceptance criterion holds within oidf; a differential fuzz of old against new checkers (922k inputs) found no difference.
<!-- SECTION:NOTES:END -->
