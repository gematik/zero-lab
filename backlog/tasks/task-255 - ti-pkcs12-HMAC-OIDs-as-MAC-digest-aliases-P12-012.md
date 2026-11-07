---
id: TASK-255
title: 'ti-pkcs12: HMAC OIDs as MAC digest aliases (P12-012)'
status: In Progress
assignee: []
created_date: '2026-11-07T17:19:00Z'
updated_date: '2026-11-07T17:58:00Z'
labels:
  - ti-pkcs12
  - spec
dependencies: []
references:
  - spec/pkcs12/README.md
priority: medium
ordinal: 271000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
spec/pkcs12 P12-012 accepts the HMAC OIDs 1.2.840.113549.2.7-11 as aliases for the MAC digests; ti-pkcs12's mac::verify matches only the digest OIDs and refuses a file whose MacData names hmacWithSHA256 as unsupported_algorithm. Found in TASK-218.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a MacData naming an hmacWith* OID verifies like its digest, with a test named after P12-012; go/pkcs12 checked for the same
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
go/pkcs12 already accepted the aliases (internal/syntax/decrypt.go macHash); ti-pkcs12 mac::verify and mac::name now do too, p12_012 test covers all ten OIDs.
<!-- SECTION:NOTES:END -->
