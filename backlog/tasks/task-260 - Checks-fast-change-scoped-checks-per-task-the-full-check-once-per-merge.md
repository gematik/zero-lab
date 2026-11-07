---
id: TASK-260
title: 'Checks: fast, change-scoped checks per task, the full check once per merge'
status: To Do
assignee: []
created_date: '2026-11-07T18:29:00Z'
labels:
  - rust
  - go
  - chore
dependencies: []
references:
  - docs/conventions/git-and-releases.md
  - rust/docs/development.md
priority: medium
type: task
ordinal: 276000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Running the full just check after a task costs 15 to 25 minutes in rust/ (fmt, clippy, doc, nextest over the workspace, wasm32, unsafe-free, core-deps, jwz backends and rsa guard, machete, deny, vet, brainpool absence) and several minutes in go/. In the batches of 2026-11-07 it ran several times per batch, occupied the shared target directory (mutation runs and other builds waited or slowed down, cargo-mutants' baseline timed out), and a spurious stamp failure (jwz browser stamp after a workspace Cargo.toml change) showed only at the end. A task needs the checks its change can affect; the full check belongs once before a merge, and in CI.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a recipe per workspace (e.g. just check-changed) runs fmt, clippy, tests and the per-crate checks only for the crates or modules a diff against main touches, plus their dependents
- [ ] #2 slow workspace-wide checks run only when their inputs changed: deny, vet and unsafe-free on Cargo.lock or a Cargo.toml, wasm32 on a core crate, the jwz stamps and backends on jwz or the workspace manifest
- [ ] #3 the full just check stays the gate before a merge and in CI, unchanged in what it checks
- [ ] #4 docs/conventions (git and releases or development) and CLAUDE.md say which check runs when, and agents follow it
- [ ] #5 measured: the change-scoped check for a one-crate change, and the full check, with their times recorded
<!-- AC:END -->
