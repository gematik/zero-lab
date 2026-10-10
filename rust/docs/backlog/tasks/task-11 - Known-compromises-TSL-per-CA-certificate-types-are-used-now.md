---
id: TASK-11
title: 'Known compromises: TSL per-CA certificate types are used now'
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - docs
dependencies: []
references:
  - docs/development.md
priority: medium
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/development.md still says the TSL's per-CA metadata (allowed certificate types, SE_1061) is unused. ti-pki checks them since TUC_PKI_007 (cert_type_ca_not_authorized, cert_type_unchecked; profiles describe --env lists the CAs). Update or remove the row.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the Known compromises table matches what ti-pki does with the TSL
<!-- AC:END -->
