---
id: TASK-217
title: 'idpd: tests named after the requirement they prove'
status: Done
assignee: []
created_date: '2026-11-05T21:24:00Z'
updated_date: '2026-11-07T10:44:00Z'
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
- [x] #1 idpd's security tests carry the requirement they prove, in the prefixes TASK-83 introduced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-07, go-batch 5e585f11: TestServerRule14_ALoginLogsNoSecretAtDebug, TestOIDCCore_3_1_3_7_ExchangeRefusesAnIDTokenOfAnotherLogin, TestOIDCCore_3_1_3_3_ExchangeRefusesAResponseWithoutAnIDToken (the last one also cited its requirement only in a comment).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
idpd's security tests carry their requirement (ServerRule14, OIDCCore_3_1_3_3, OIDCCore_3_1_3_7). Merged from go-batch.
<!-- SECTION:FINAL_SUMMARY:END -->
