---
id: TASK-88
title: 'pdp: hold the signing key as a crypto.Signer'
status: In Progress
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-01T19:49:00Z'
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
- [x] #1 the AS signs through a crypto.Signer created at the edge; no private JWK held in the server
- [x] #2 a missing or unreadable signing key fails start-up; no random fallback key
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Finding (2026-11-01, stacks analysis TASK-165): go/pdp/authzserver/server.go:203-227 reads the signing key from a JWK file and, when the file cannot be loaded, falls back to a random key with a warning. For a zero-trust PDP that is a start-up failure, not a degraded mode (servers.md rule 17). TASK-170 (HSM binding) builds on this task.

2026-11-01: authzserver.Config.SigningKey holds a crypto.Signer and a kid; the commands zero-pdp and zero-bff-pdp build it with Config.LoadSigningKey at the edge, and New fails without one. The random fallback is gone; the file's bytes are cleared after parsing. The key is checked to be on P-256 for ES256. Other config files are still read inside authzserver.New; that is outside this task. Verified: unit tests with a counting signer, just check, and the real zero-pdp without a key (exit 1, names the reason) and with one against the Smoke, Regression and Flow e2e suites. TASK-170 can hand in an HSM-backed signer through the same field.
<!-- SECTION:NOTES:END -->
