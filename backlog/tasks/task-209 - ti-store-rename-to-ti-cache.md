---
id: TASK-209
title: 'ti-store: rename to ti-cache'
status: To Do
assignee: []
created_date: '2026-11-03T20:41:00Z'
labels:
  - ti-store
  - ti-pki
  - ti-connector-client
  - chore
dependencies:
  - TASK-208
references:
  - rust/ti-store/README.md
  - rust/docs/design.md
priority: low
ordinal: 216000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After TASK-208 the crate holds only the HTTP cache: Cache, CachePolicy, CacheStore and their types, with no store left. The name now misleads, and it was ti-cache before TASK-103.2 renamed it for the store module. ti-pki (feature load) and ti-connector-client depend on it, and ti-pki re-exports its types from load/mod.rs, so the rename changes imports in those crates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The crate is rust/ti-cache, package ti-cache, and no reference to ti-store or ti_store remains outside rust/ReleaseNotes.md history and the backlog
- [ ] #2 ti-pki's public re-exports keep their names, and only the crate they come from changes
- [ ] #3 rust/ReleaseNotes.md records the rename
- [ ] #4 just check passes in rust/
<!-- AC:END -->
