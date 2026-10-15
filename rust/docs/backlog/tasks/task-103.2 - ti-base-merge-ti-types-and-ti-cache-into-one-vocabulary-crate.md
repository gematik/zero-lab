---
id: TASK-103.2
title: 'ti-store: rename ti-cache to ti-store'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 19:04'
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
Published crates should not multiply. ti-cache becomes ti-store, the one crate for client storage: today the cache policy and the CacheStore trait, from TASK-103.3 also the sealed store of spec/store. ti-types stays as it is: its admission rule (no_std, no I/O, no async) and its stability promise rule out merging storage into it (decision of the maintainer, 2026-10-15). Mechanical: no behaviour change; ti-cache was never released.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-cache is gone from the workspace; ti-store provides the same API under ti_store
- [x] #2 all dependents build and just check passes unchanged
- [x] #3 docs, READMEs and release notes name ti-store
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done mechanically: git mv ti-cache ti-store, ti_cache -> ti_store in code, Cargo manifests, Justfile (wasm32), READMEs, design docs, go/docs/design.md and the unreleased release notes; cargo fmt for the new import order. The jwz browser stamp hashes the workspace Cargo.toml and was regenerated with just jwz-recheck (browser tests passed). just check green: 608 tests passed, 3 skipped (gated).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-cache renamed to ti-store (no behaviour change); ti-types unchanged. All dependents, docs and the unreleased release notes updated; jwz browser stamp regenerated; just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
