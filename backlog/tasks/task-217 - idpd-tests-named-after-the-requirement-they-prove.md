---
id: TASK-217
title: 'idpd: tests named after the requirement they prove'
status: To Do
assignee: []
created_date: '2026-11-05T21:24:00Z'
labels:
  - go
dependencies: []
ordinal: 224000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-83 covered pdp, pep, openid, oidf, nonce and epa. idpd still has TestALoginLogsNoSecretAtDebug and TestExchangeRefusesAnIDTokenOfAnotherLogin, names that pdp and openid used before TASK-83.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 idpd's security tests carry the requirement they prove, in the prefixes TASK-83 introduced
<!-- AC:END -->
