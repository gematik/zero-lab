---
id: TASK-216
title: 'epa: tests for A_24477 and A_27671'
status: In Progress
assignee: []
created_date: '2026-11-05T21:24:00Z'
updated_date: '2026-11-07T10:40:00Z'
labels:
  - go
dependencies: []
ordinal: 223000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
epa has no test for A_24477 (VAU-nonPU-Tracing header) and none for A_27671 (single-use token), although entitlements.go cites A_27671. Found while naming tests (TASK-83).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a test named after A_24477 proves the tracing header rule
- [x] #2 a test named after A_27671 proves the single-use token rule
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-07, go-batch 8a7d150a: A_24477 (gemSpec_Krypt 2.50.0) was not implemented: a nonPU channel now sends VAU-nonPU-Tracing (base64 K2_c2s_app_data, space, K2_s2c_app_data) on every outer request after the key exchange, a PU channel never. The A_27671 test found the PoPP token (and every request in plain) in the debug log: Channel.EncryptRequest logged the dumped request; it now logs its size. The test VAU server logs the decrypted request's size instead of its content. Tests: TestA_24477_ANonPUChannelDisclosesItsKeysOnEveryRequest, TestA_24477_AProductionChannelNeverDisclosesItsKeys, TestA_27671_APoPPTokenIsSentOnceAndNeverLogged.
<!-- SECTION:NOTES:END -->
