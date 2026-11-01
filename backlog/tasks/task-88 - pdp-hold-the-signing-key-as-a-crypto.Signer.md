---
id: TASK-88
title: 'pdp: hold the signing key as a crypto.Signer'
status: To Do
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - pdp
  - keys
dependencies: []
references:
  - docs/design/keys.md
  - go/docs/design.md
priority: high
ordinal: 86000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pdp/authzserver holds its signing key as a jwk.Key loaded from a file (private-key rule 1).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the AS signs through a crypto.Signer created at the edge; no private JWK held in the server
- [ ] #2 a missing or unreadable signing key fails start-up; no random fallback key
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Finding (2026-11-01, stacks analysis TASK-165): go/pdp/authzserver/server.go:203-227 reads the signing key from a JWK file and, when the file cannot be loaded, falls back to a random key with a warning. For a zero-trust PDP that is a start-up failure, not a degraded mode (servers.md rule 17). TASK-170 (HSM binding) builds on this task.
<!-- SECTION:NOTES:END -->
