---
id: TASK-396
title: 'kv: Keyring and Keychain read their file at start and follow it no more'
status: Done
assignee: []
created_date: '2026-11-19 13:53'
updated_date: '2026-11-22 11:56'
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
- [x] #1 LoadKeyring and LoadKeychain read and check the file once; Current and Lookup do no file I/O
- [x] #2 zero-pep-proxy's flag help (main.go:51) and its at-rest encryption document say that a new key takes effect with a rollout
- [x] #3 The release notes of go/kv state the change of behaviour for users who relied on the file being followed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: documents that promise the file following and change with the code: go/pep/proxy/docs/at-rest-encryption.md:68 ('Rotation needs no restart: each replica looks at the file at most every 30 s'), go/pep/proxy/cmd/zero-pep-proxy/main.go:51 (flag help), go/pdp/cmd/zero-pdp/CONFIG.md:41 (zero-pdp, frozen: changed when work on it resumes, or with this task if the maintainer says so). The rotation order with an overlap (new key second, then first, then the old one removed) stays; each step becomes a rollout.

2026-11-19: done on feat/ti-hsm-spike. LoadKeyring and LoadKeychain read their file once; Current, Lookup, Entries, Revoked, Ready and NameKeys do no file I/O; the keychain unwraps every entry at parse (no reuse of known entries); readKeyringFile no longer stats. Removed: the 30 s following, keyringCheckEvery, SetKeyringClock (export_test.go), and WithKeychainCheck, which only looked at a changed file and would otherwise be an option without effect; a consumer checks the file it starts with through Entries and Revoked. Tests: TestKeyring_TheFileIsReadOnceAtStart, TestKeychainReadsItsFileOnceAtStart (a changed or broken file changes nothing and asks the key service nothing; a keychain loaded after the change has the new entry, opens what v1 sealed, loses only what a revoked entry sealed), TestLoadKeyring_RefusesABrokenFileAtStart (no file content in the error). zero-pep-proxy's flag help and docs/at-rest-encryption.md: rotation as rollouts. zero-pdp/CONFIG.md:41 left (frozen). Go writes a module's release notes when it is tagged (git-and-releases.md); the entry for the next go/kv tag (v0.6.0, breaking): '### breaking — LoadKeyring and LoadKeychain read their file once, at start, and no longer follow it; a changed file takes effect with a rollout (servers.md rule 8). WithKeychainCheck is removed: it looked only at a changed file; a consumer holds the file it starts with against what is sealed through Entries and Revoked.' External user to tell: zeta-pdp-go (internal/host/keychain.go uses LoadKeychain with WithKeychainCheck; its decision-15 describes the rotation by file following).

2026-11-19: zeta-pdp-go TASK-158 adapts its keychain to v0.6.0 (no WithKeychainCheck, the check at start); TASK-159 checks its own file following (signing keys every 30 s, attestation and backend files) against rule 8.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
LoadKeyring and LoadKeychain read their file once, at start; Current, Lookup and the others do no file I/O; WithKeychainCheck is removed. zero-pep-proxy's help and docs/at-rest-encryption.md describe rotation as rollouts. Released as go/kv v0.6.0 (2026-11-22), whose release notes state the breaking change. No external user to tell: the maintainer, 2026-11-22, we are its only user.
<!-- SECTION:FINAL_SUMMARY:END -->
