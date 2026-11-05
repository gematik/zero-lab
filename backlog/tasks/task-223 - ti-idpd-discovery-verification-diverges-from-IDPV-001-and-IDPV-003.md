---
id: TASK-223
title: 'ti-idpd: discovery verification diverges from IDPV-001 and IDPV-003'
status: To Do
assignee: []
created_date: '2026-11-05T22:03:00Z'
labels:
  - ti-idpd
  - security
dependencies: []
priority: high
ordinal: 230000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-50: ti-idpd verifies the discovery document's signature with the x5c key before the trust check, where IDPV-001 asks for the trust check first, and it accepts unchecked certificates with a warning (Checked::Unchecked), against IDPV-003 / A_20617-01. The idpv_001 tests prove only that a refused certificate stops the flow.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the signer's certificate is checked before its key is used (IDPV-001), with a test that fails against the current order
- [ ] #2 an unchecked certificate stops the flow, or the exception is decided and recorded with its reason (IDPV-003, A_20617-01)
<!-- AC:END -->
