---
id: TASK-120.6
title: 'go/tirpc: stdlib-only Go client for ti helpers'
status: To Do
assignee: []
created_date: 2026-10-20 14:07
updated_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - interop
dependencies:
  - TASK-120.2
parent_task_id: TASK-120
priority: low
ordinal: 131000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Module go/tirpc, standard library only: finding a helper (TI_<GROUP>_HELPER_PATH, then <program dir>/../libexec/telematik, then the program's own directory; never PATH); an optional pinned SHA-256 checked before start (on Linux by executing the verified file descriptor, elsewhere from a private copy); the handshake; the JSON-lines client with context deadlines and size limits; restart after a crash, failing only calls in flight. Typed clients tirpc/pki and tirpc/idpd. Tests against a fake helper and the real ones; fuzzing of the answer parser.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 lookup, pinning and handshake
- [ ] #2 typed clients tirpc/pki and tirpc/idpd
- [ ] #3 tests against fake and real helpers, fuzzing
- [ ] #4 Unix-socket mode to a sidecar tested; no secret in any request or answer
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01 (decision-10): the client supports both the stdio child and a Unix socket to a sidecar started from the same image; the digest manifest and signature checks apply to the child mode, the image digest covers the sidecar mode. Secrets never cross the socket.
<!-- SECTION:NOTES:END -->
