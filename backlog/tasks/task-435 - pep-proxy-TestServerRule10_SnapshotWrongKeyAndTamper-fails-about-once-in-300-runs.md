---
id: TASK-435
title: >-
  pep/proxy: TestServerRule10_SnapshotWrongKeyAndTamper fails about once in 300
  runs
status: To Do
assignee: []
created_date: '2026-11-25T19:40:00Z'
labels:
  - go
  - testdata
dependencies: []
priority: low
ordinal: 448000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Seen on 2026-11-25 in just check on a branch that does not touch pep/proxy: snapshot_test.go:86, 'tampered snapshot opened (AEAD should reject)'. Repeated alone: 10 failures in 3000 runs (go test ./pep/proxy -run TestServerRule10_SnapshotWrongKeyAndTamper -count=3000). The test alters the token by replacing its last two characters with 'xy'. Read from the test, not proven: when the token ends in those characters already, or the replacement changes only bits the token's encoding ignores, the altered token is the same sealed bytes and opens, as it should. That would be a fault of the test, not of the sealing; to be confirmed by decoding both tokens in a failing run before the test is changed. A check that fails by chance costs a rerun of just check and hides a real failure of the same test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The cause is established from a failing run: whether the altered token decodes to the same bytes
- [ ] #2 The test alters the sealed bytes themselves (a bit of the ciphertext, of the tag, of the nonce), and passes 100000 runs
- [ ] #3 If the altered token differs in its bytes and opens, this is a defect of the sealing and becomes its own task with high priority
<!-- AC:END -->
