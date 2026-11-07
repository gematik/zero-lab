---
id: TASK-260
title: 'Workflow: several tasks per branch, one full check per merge'
status: Done
assignee: []
created_date: '2026-11-07T18:29:00Z'
updated_date: '2026-11-07T18:54:00Z'
labels:
  - rust
  - go
  - chore
dependencies: []
references:
  - docs/conventions/backlog.md
  - docs/conventions/git-and-releases.md
priority: medium
type: task
ordinal: 276000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer, 2026-11-07: branches are bigger and carry several tasks; the full check runs once per branch, before its merge, and not per task. Today the rules say otherwise: docs/conventions/backlog.md (Working a task, step 1) has one branch per task, and CLAUDE.md asks for just check in each workspace a change touches, which agents read as per task. A full just check costs 15 to 25 minutes in rust/ and several in go/; in the batches of 2026-11-07 it ran several times, held the shared target directory (mutation runs slowed down, cargo-mutants' baseline timed out), and a stale jwz stamp showed only at the end.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 docs/conventions/backlog.md and git-and-releases.md: a branch carries several tasks; each task is still started, noted and closed in the backlog, and its commits name it; Done is set when the branch merges
- [x] #2 the documents and CLAUDE.md say which checks run when: while working, the changed module's fast checks (fmt, clippy, its tests, in its feature combinations); the full just check of each touched workspace once, before the branch merges; CI runs it on every push
- [x] #3 a recipe per workspace (e.g. just check-changed) runs the fast checks for the crates or modules a diff against main touches, plus their dependents, so the scope need not be picked by hand
- [x] #4 the full check's slow parts that depend on few inputs say so (deny, vet, unsafe-free on Cargo.lock and manifests; jwz stamps on jwz and the workspace manifest), so a stale stamp or a vet gap is found when its input changes, not only at the merge
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC 2 adjusted openly: the repository has no CI (.github is absent), so the full just check before the merge is the only gate; the pull request reports it. Done: backlog.md (a branch carries several tasks, Done on merge), git-and-releases.md (checks follow the branch: check-changed while working, the full check once before the merge), CLAUDE.md, testing.md, rust development.md. rust: just check-changed [base] via scripts/changed.py (changed crates and their dependents from cargo metadata, with unit tests in scripts/test_changed.py); wasm32 only for core crates, nonprod-absent for ti-pki, unsafe-free/core-deps/jwz-backends/machete/deny/vet only when a manifest, the lock, supply-chain or unsafe-exceptions.md changed, scripts-test for scripts/. go: just check-changed [base] runs lint, golangci, modernize and test for the changed modules and those that require them (GO_MODULES narrows _each and _each_check); race, vuln, mod-check and api-lint stay in check. modernize ignores go: downloading lines (a cold module cache failed it). Measured on 2026-11-07: rust check-changed on this branch (ti-pkcs12, ti-cli, ti-connector-client, manifests, scripts) 219 s against 15 to 25 min for just check; go check-changed for tipki and its four dependents 34 s.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Branches carry several tasks; while working just check-changed (rust: changed crates and dependents via scripts/changed.py, slow checks by input; go: changed modules and those requiring them), the full just check once before the merge. Documented in backlog.md, git-and-releases.md, CLAUDE.md, testing.md, rust development.md. Measured: rust 219 s against 15-25 min, go 34 s for five modules. No CI exists, so the pre-merge check is the gate.
<!-- SECTION:FINAL_SUMMARY:END -->
