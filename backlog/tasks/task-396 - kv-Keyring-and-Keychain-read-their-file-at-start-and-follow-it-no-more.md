---
id: TASK-396
title: 'kv: Keyring and Keychain read their file at start and follow it no more'
status: To Do
assignee: []
created_date: '2026-11-19 13:53'
updated_date: '2026-11-19 13:53'
labels:
  - go
  - kv
dependencies:
  - TASK-395
references:
  - go/kv/keyring.go
  - go/kv/keychain.go
priority: medium
ordinal: 409000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
LoadKeyring and LoadKeychain follow their file: at most every 30 s, inside Current and Lookup, they compare mtime and size and read and parse the file again (and unwrap the new entries of a keychain). Under the rule of TASK-395 keys are read at start and changed by a rollout (rule 8), rotating with an overlap (rule 22), so the following is code without a purpose; it also does file I/O on the request path, which rule 8 keeps trust material out of. Users: zero-pep-proxy (cmd/zero-pep-proxy/main.go:167, the session key and the at-rest encryption key), zero-pdp (cmd/zero-pdp/start.go:161 and :177, frozen), and outside the repository zeta-pdp-go (TASK-141). go/kv is a published module (v0.5.0): the change of behaviour goes into its release notes and a tag of its own.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 LoadKeyring and LoadKeychain read and check the file once; Current and Lookup do no file I/O
- [ ] #2 zero-pep-proxy's flag help (main.go:51) and its at-rest encryption document say that a new key takes effect with a rollout
- [ ] #3 The release notes of go/kv state the change of behaviour for users who relied on the file being followed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: documents that promise the file following and change with the code: go/pep/proxy/docs/at-rest-encryption.md:68 ('Rotation needs no restart: each replica looks at the file at most every 30 s'), go/pep/proxy/cmd/zero-pep-proxy/main.go:51 (flag help), go/pdp/cmd/zero-pdp/CONFIG.md:41 (zero-pdp, frozen: changed when work on it resumes, or with this task if the maintainer says so). The rotation order with an overlap (new key second, then first, then the old one removed) stays; each step becomes a rollout.
<!-- SECTION:NOTES:END -->
