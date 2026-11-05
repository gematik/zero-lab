---
id: TASK-215
title: 'pep: RFC 8414 test names claim more than the RFC requires'
status: To Do
assignee: []
created_date: '2026-11-05T21:24:00Z'
labels:
  - go
dependencies: []
ordinal: 222000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TestRFC8414_MetadataOfAnHTTPSIssuerNeedsHTTPSEndpoints and its sibling cite RFC 8414, which requires https only for the issuer and jwks_uri (Section 2), not for every endpoint. Found while naming tests (TASK-83).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the tests cite the rule that requires https endpoints, or are split into an RFC 8414 test and a test of our own policy
<!-- AC:END -->
