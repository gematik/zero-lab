---
id: TASK-204
title: 'tipki: binary OIDs (x509.OID) in the API, for go/tipki v0.30.0'
status: Done
assignee: []
created_date: '2026-11-03T17:16:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - tipki
dependencies: []
ordinal: 211000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
tipki carries OIDs as dotted strings, so a wrong value only fails at runtime and every compare allocates. Rust's ti-pki already uses a binary type. Move the public API and the tables to crypto/x509.OID before the first tag, go/tipki v0.30.0, so that consumers such as ehca port once. Text stays at the edges: gemSpec tables, TSL XML, spec/ test data and JSON. Tagging is a separate step.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The oid package's identifiers and tipki's public API carry x509.OID, not dotted strings
- [x] #2 OID text from a TSL is parsed strictly: a non-canonical spelling such as 1.2.276.0.76.4.030 is refused
- [x] #3 Every table entry's identifier is pinned against spec/pki-profiles
- [x] #4 An empty OID matches no certificate type, role or table entry
- [x] #5 The tables follow gemSpec_OID 3.26.0 like ti-pki (TASK-199)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
x509.OID throughout tipki's API and tables; oid.Parse is strict, since x509.ParseOID reads 1.2.030 as 1.2.30; oid.MustParse for source. encoding/asn1 values from the standard library (extension IDs, EKU, OCSP) are compared with EqualASN1OID, not converted. TSL location markers stay text: they are matched against text in the list. Not tagged. idpd still pins tipki by pseudo-version until just sync at the tag.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/tipki takes and returns binary OIDs (x509.OID), released as v0.30.0.
<!-- SECTION:FINAL_SUMMARY:END -->
