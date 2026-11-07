---
id: TASK-260
title: 'Workflow: several tasks per branch, one full check per merge'
status: To Do
assignee: []
created_date: '2026-11-07T18:29:00Z'
updated_date: '2026-11-07T18:31:00Z'
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
- [ ] #1 docs/conventions/backlog.md and git-and-releases.md: a branch carries several tasks; each task is still started, noted and closed in the backlog, and its commits name it; Done is set when the branch merges
- [ ] #2 the documents and CLAUDE.md say which checks run when: while working, the changed module's fast checks (fmt, clippy, its tests, in its feature combinations); the full just check of each touched workspace once, before the branch merges; CI runs it on every push
- [ ] #3 a recipe per workspace (e.g. just check-changed) runs the fast checks for the crates or modules a diff against main touches, plus their dependents, so the scope need not be picked by hand
- [ ] #4 the full check's slow parts that depend on few inputs say so (deny, vet, unsafe-free on Cargo.lock and manifests; jwz stamps on jwz and the workspace manifest), so a stale stamp or a vet gap is found when its input changes, not only at the merge
<!-- AC:END -->
