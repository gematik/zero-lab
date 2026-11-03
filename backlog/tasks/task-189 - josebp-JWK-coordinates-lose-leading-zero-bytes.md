---
id: TASK-189
title: 'josebp: JWK coordinates lose leading zero bytes'
status: Done
assignee: []
created_date: '2026-11-02T18:08:00Z'
updated_date: '2026-11-02T19:06:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 199000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
JSONWebKey.MarshalJSON writes x, y and d with big.Int.Bytes(), which drops leading zeros, so about 2 keys in 256 have a short coordinate. RFC 7518 6.2.1.2 and 6.2.2.1 require the full length. It reaches the epk of every JWE sent to the IDP, so about 0.8% of encrypted challenges and token keys carry a malformed key, and TestJWECross failed at that rate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Coordinates are the curve's full length, proven with a key whose coordinate starts with a zero byte
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
JWK coordinates are written at the curve's full length (RFC 7518).
<!-- SECTION:FINAL_SUMMARY:END -->
