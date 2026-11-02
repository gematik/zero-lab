---
id: TASK-174
title: 'Go: align package and module names with the Rust crates'
status: Done
assignee: []
created_date: '2026-11-01T16:47:00Z'
updated_date: '2026-11-02T20:36:00Z'
labels:
  - go
  - chore
  - docs
dependencies: []
priority: low
ordinal: 184000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The maintainer asked (2026-11-01, while starting TASK-166) to consider renaming the Go packages according to the Rust crates, so the same function carries the same name in both stacks (ti-pki, ti-idpd, ti-jwz, ti-pkcs12, ti-store on the Rust side; gemidp, brainpool, pkcs12, store, dpop, oidf, oauth on the Go side). Evaluate: which Go modules correspond to a Rust crate, what a rename costs consumers (module paths are public API; go/<module>/vX.Y.Z tags; a rename is a new module path with a deprecation period), and whether a naming rule belongs in docs/conventions/naming-and-config.md (one name per function across languages) or only in the inventory of doc-2. Rules: docs/conventions/naming-and-config.md; docs/conventions/git-and-releases.md (versions and tags).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the correspondence table Go module to Rust crate recorded with the recommendation per module (rename, keep, archive)
- [x] #2 a naming rule proposed or the reason against one recorded
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/gemidp is go/idpd, in code and everything operators see. The naming rule and correspondence are in docs/conventions/naming-and-config.md.
<!-- SECTION:FINAL_SUMMARY:END -->
