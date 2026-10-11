---
id: TASK-38
title: 'Go tooling: staticcheck fails against the go1.27 toolchain; tag brainpool'
status: In Progress
assignee: []
created_date: '2026-10-11 11:48'
updated_date: '2026-10-11 12:01'
labels:
  - go
  - tooling
dependencies: []
priority: medium
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/ just check fails in staticcheck for every module (staticcheck 2026.1 built for an older export data version than go1.27.2: export data version 5); identical on main, so module checks rely on go vet and tests. Update staticcheck (or pin it through go tool) so just check is green again. Also go/brainpool has an untagged commit since v1.1.0 (60dc963, versioned local replaces): tag v1.1.1 if it changes what consumers (ehca-go) get, else note why not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cd go && just check green
- [x] #2 go/brainpool tagged or the reason recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-10-11. Cause: Go 1.27 writes export data version 5; staticcheck 2026.1 (v0.7.0) reads up to 2, the newest release 2026.2.1 (v0.8.1) up to 4, so every package load failed under the local go1.27.2 (the modules declare go 1.26.4, GOTOOLCHAIN=auto uses the newer local Go). Pinned the development build v0.7.0-0.dev.0.20261009230814-452d5bb86b45, which reads version 5; move to the first release that does. Findings after months without staticcheck, fixed: brainpool receiver names (Select), local *Json names, a redundant type; epa vau ECDH key built with ecdh.P256().NewPublicKey instead of the deprecated ecdsa X/Y; gemidp test compares keys with PublicKey.Equal; pdp unused test helper removed. Suppressed with reasons: brainpool's exported josebp fields HeadersJson/PayloadJson (renaming breaks v1), Point.Add's receiver q (nistec convention). modernize: recipe skips generated files (addchain, Fiat), fixes applied in brainpool tests, kv, pep; three ineffective omitempty on time.Time removed (no output change). go/brainpool needs no tag: the commit since v1.1.0 only adds a go.sum line. cd go && just check is green; vet and tests green for all 14 modules.
<!-- SECTION:NOTES:END -->
