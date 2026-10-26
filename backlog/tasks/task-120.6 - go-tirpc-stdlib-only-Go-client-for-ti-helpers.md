---
id: TASK-120.6
title: 'go/tirpc: stdlib-only Go client for ti helpers'
status: To Do
assignee: []
created_date: '2026-10-20 14:07'
updated_date: '2026-10-20 19:57'
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
<!-- AC:END -->
