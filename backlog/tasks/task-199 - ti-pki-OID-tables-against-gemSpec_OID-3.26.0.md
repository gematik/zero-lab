---
id: TASK-199
title: 'ti-pki: OID tables against gemSpec_OID 3.26.0'
status: Done
assignee: []
created_date: 2026-10-28 08:25
updated_date: '2026-11-05T19:19:00Z'
labels:
  - ti-pki
  - spec
dependencies: []
references:
  - rust/ti-pki/src/oid.rs
  - https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/
priority: medium
ordinal: 158000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/ti-pki/src/oid.rs states its tables are complete as of gemSpec_OID V3.25.0 with C_12646 applied. gemSpec_OID 3.26.0 (19.09.2026, CI_26_4) is released; CI_26_4 changes gemSpec_OID for the ZETA Guard AUT certificate and the Forschungsdatenzentrum's C.FD.AUT. The tables have not been compared with 3.26.0, found while adding dipag-vau-aut.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 every Tab_PKI_401-406 row of gemSpec_OID 3.26.0 matches oid.rs (OID, reference, description, certificate types)
- [x] #2 the module header names 3.26.0 and drops the pending-change note if 3.26.0 contains C_12646
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
3.26.0 differs from the draft C_12646 the tables had applied: oid_zeta-prv-approv is present, ZETA Guard is C.FD.AUT only. Followed the released table and dropped the note. Spec spellings left as they are in ours: oid_mobile_einrichtung_rettungsdienst (spec has a stray space) and Komponentenzertifikate (spec: Komponenten-zertifikate).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-pki's OID tables follow gemSpec_OID 3.26.0.
<!-- SECTION:FINAL_SUMMARY:END -->
