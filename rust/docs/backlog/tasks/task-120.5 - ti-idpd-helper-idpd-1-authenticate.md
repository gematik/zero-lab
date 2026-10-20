---
id: TASK-120.5
title: 'ti-idpd-helper: idpd/1 (authenticate)'
status: To Do
assignee: []
created_date: '2026-10-20 14:07'
updated_date: '2026-10-20 19:57'
labels:
  - rust
  - idpd
dependencies:
  - TASK-120.3
  - TASK-120.4
parent_task_id: TASK-120
priority: low
ordinal: 130000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/helpers/idpd, crate and binary ti-idpd-helper. Method authenticate with the schema of ti idpd authenticate. Identity from PKCS#12, PEM or a Konnektor card; secrets only as file paths (p12_password_path, key_path), never as values. The IDP's certificates are checked against the TSL as ti does (TASK-27), in either trust mode. Network only to the IDP-Dienst and the Konnektor.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 authenticate answers as ti idpd authenticate does
- [ ] #2 secrets only as file paths
- [ ] #3 IDP certificates checked against the TSL in both trust modes
<!-- AC:END -->
