---
id: TASK-103.2
title: 'ti-base: merge ti-types and ti-cache into one vocabulary crate'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - ti-cli
  - ti-pki
  - chore
dependencies: []
references:
  - rust/docs/design.md
parent_task_id: TASK-103
priority: medium
ordinal: 103000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Published crates should not multiply, and a published crate's dependencies must be published too: ti-pki pulls in ti-types (time, env) and ti-cache (cache policy, store trait). Merge them into ti-base (ti_base::{time,env,cache}) before the store module lands there. Mechanical: no behaviour change.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-types and ti-cache are gone from the workspace; ti-base provides time, env and cache
- [ ] #2 all dependents build and just check, just core-deps, just wasm32 pass unchanged
- [ ] #3 rust/docs/design.md and other docs name ti-base
<!-- AC:END -->
