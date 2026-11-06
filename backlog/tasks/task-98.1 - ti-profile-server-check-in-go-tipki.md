---
id: TASK-98.1
title: ti profile server check in go/tipki
status: To Do
assignee: []
created_date: '2026-11-06T14:01:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 244000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ServerCheck in go/tipki following ti_pki::tls (TLSV rules of the ti profile): validator without revocation, signature algorithm, name (SAN/CN, wildcards), OCSP stapled within the grace else the responder. Passes the ti cases of spec/pki-validation/testdata.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the ti corpus cases pass with the codes the manifest expects
<!-- AC:END -->
