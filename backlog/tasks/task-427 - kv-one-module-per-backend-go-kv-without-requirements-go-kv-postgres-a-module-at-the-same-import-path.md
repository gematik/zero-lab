---
id: TASK-427
title: >-
  kv: one module per backend: go/kv without requirements, go/kv/postgres a
  module at the same import path
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
labels:
  - go
dependencies: []
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: high
ordinal: 440000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Step 0 of doc-7 (Module structure, Migration). Today kv/postgres is a package of module go/kv, so every consumer of kv has pgx and its five requirements in its module graph, and a MariaDB backend as a third package would add its driver to all of them. Cut: go/kv keeps kv and kv/revoked and requires nothing outside the standard library; go/kv/postgres becomes a module of its own with the same import path, unchanged in behaviour. The first go/kv/postgres requires the go/kv release that no longer contains the package, so that version selection never pairs an old go/kv with it (ambiguous import); both are tagged from one commit, go/kv first. Nothing else changes in this step, so that a mistake in the cut shows alone. zero-pep-proxy, zaddy and the frozen zero-pdp only gain the requirement; they stay on Postgres (decided 2026-11-25).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/kv's go.mod has no requirement; go/kv/postgres is a module in go.work with the same import path, requiring pgx and the go/kv release without the package
- [ ] #2 A build outside the workspace of a consumer that requires both resolves the package once: shown by a test module, also against the previous go/kv
- [ ] #3 zero-pep-proxy, zaddy and zero-pdp build and pass with the new requirement and no change of code
- [ ] #4 go.work, the Justfile's module lists, just sync, AGENTS.md (a row for go/kv/postgres), the gated-suite table and ReleaseNotes follow; just check passes
<!-- AC:END -->
