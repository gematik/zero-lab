---
id: TASK-330
title: >-
  pdp: tokens issued from an authorization code are revoked when the code is
  used again
status: To Do
assignee: []
created_date: '2026-11-15T09:24:00Z'
updated_date: '2026-11-15T14:09:00Z'
labels:
  - pdp
  - go
  - security
dependencies: []
ordinal: 345000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-316 makes a code single use (a second use gets invalid_grant). RFC 6749 section 10.5 adds: the server SHOULD revoke all tokens previously issued from that code. With kv Take the second use finds nothing, so a revocation needs a marker of used codes (code hash to the issued tokens' session) kept until the code would have expired. Server rule 15 treats an optional security feature as mandatory unless interop says otherwise.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A second use of a code is refused and revokes the access and refresh tokens issued from its first use, shown through the HTTP handlers
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Archived 2026-11-15: zeta-pdp-go replaces zero-pdp; the property moves to zeta-pdp-go TASK-106.
<!-- SECTION:NOTES:END -->
