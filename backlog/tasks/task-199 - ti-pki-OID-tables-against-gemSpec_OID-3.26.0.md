---
id: TASK-199
title: 'ti-pki: OID tables against gemSpec_OID 3.26.0'
status: To Do
assignee: []
created_date: '2026-10-28 08:25'
labels:
  - ti-pki
  - spec
dependencies: []
references:
  - rust/ti-pki/src/oid.rs
  - 'https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/'
priority: medium
ordinal: 158000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/ti-pki/src/oid.rs states its tables are complete as of gemSpec_OID V3.25.0 with C_12646 applied. gemSpec_OID 3.26.0 (19.09.2026, CI_26_4) is released; CI_26_4 changes gemSpec_OID for the ZETA Guard AUT certificate and the Forschungsdatenzentrum's C.FD.AUT. The tables have not been compared with 3.26.0, found while adding dipag-vau-aut.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every Tab_PKI_401-406 row of gemSpec_OID 3.26.0 matches oid.rs (OID, reference, description, certificate types)
- [ ] #2 the module header names 3.26.0 and drops the pending-change note if 3.26.0 contains C_12646
<!-- AC:END -->
