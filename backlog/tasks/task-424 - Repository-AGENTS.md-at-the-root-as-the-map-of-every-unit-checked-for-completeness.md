---
id: TASK-424
title: >-
  Repository: AGENTS.md at the root as the map of every unit, checked for
  completeness
status: In Progress
assignee: []
created_date: '2026-11-24T21:53:00Z'
updated_date: '2026-11-25T06:08:00Z'
labels:
  - docs
  - agents
dependencies: []
priority: medium
ordinal: 437000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
An agent that reads the repository, to work in it or to use one of its building blocks, has no map: the table of the root README misses egress, tipki, oidftest, ti-client, ti-tls and ti-hsm-proxy, rust/README.md names 2 of the crates, and 10 Go modules have no README, so an agent opens every module and README to find the one it needs. A root AGENTS.md, the file agents read unasked, names every unit once: what it is, its layer, what it depends on, its commands and where to read on. It is a map, not a rule: rules stay in docs/ and CLAUDE.md, the use of a tool in the tool's own guide (docs/conventions/agents.md). Decided by the maintainer on 2026-11-24: for both kinds of agents (developing here, using a unit), at the root as AGENTS.md, with a completeness check.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 AGENTS.md at the root names every Go module of go.work and every crate of the Rust workspace with its purpose, layer, dependencies inside the repository, commands and the document to read next, the shared specifications, and a table from task to unit
- [x] #2 just check in rust/ and in go/ fails when a workspace member is missing from AGENTS.md or AGENTS.md names a unit that is gone
- [x] #3 CLAUDE.md, the root README, rust/README.md and docs/conventions/agents.md point to it instead of carrying lists of their own that can differ
- [x] #4 A release reads the rows of the units it ships and corrects them: a step of the release checklist in docs/conventions/git-and-releases.md, the rule in docs/conventions/agents.md
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-24, on chore/agents-map. AGENTS.md (122 lines): which unit for which task (19 tasks, Rust and Go side by side), 16 crates and 18 modules with layer, purpose, dependencies inside the repository and the document to read next, the 6 specifications, where the rest is. Purposes are the crates' descriptions and the modules' package comments, dependencies from cargo metadata and the go.mod files, layers from the two profiles' diagrams. just agents-map in rust/ (cargo metadata) and go/ (go.work) compares the members with the rows and is part of just check; proven to fail by removing a row. The module tables of the root README and of rust/README.md are replaced by a link; CLAUDE.md, docs/README.md and docs/conventions/agents.md (new section, The repository's map) point to it. Verified: every relative link of the touched documents resolves; just check-changed passes in rust/ and go/. Seen on the way, not changed: spec/README.md still lists Go as planned for pki-validation though tipki/titls and egress implement it; the Go profile's diagram names a library oauth that no module has; 10 Go modules have no README and are described by their package comment only.

2026-11-25, maintainer: the map is maintained at releases from now on. Releasing has a new step 4 (read the released units' rows against what ships, correct them in the release pull request); the rule itself is a bullet of The repository's map in docs/conventions/agents.md, since the completeness check proves a row exists, not that it is true.
<!-- SECTION:NOTES:END -->
