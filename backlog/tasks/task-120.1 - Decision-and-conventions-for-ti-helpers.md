---
id: TASK-120.1
title: Decision and conventions for ti helpers
status: To Do
assignee: []
created_date: 2026-10-20 14:07
updated_date: '2026-11-01T16:11:00Z'
labels:
  - docs
  - interop
dependencies: []
parent_task_id: TASK-120
priority: low
ordinal: 126000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Carry decision-8 over from branch spike/go-rust-bridge, rewritten for helpers: per-group helpers over JSON lines first; wasm2go (Rust to Wasm to Go source) only for programs that must be one go-install binary; wazero and purego rejected. Write the agreed rules into docs/interop.md (helpers as the shape of the process boundary, replacing the universal ti serve of TASK-26), docs/conventions/naming-and-config.md (ti-<group>-helper, <group>/<n>, go/tirpc/<group>, TI_<GROUP>_HELPER_PATH) and docs/conventions/git-and-releases.md (libexec/telematik layout, lookup order, digest manifest per product, ed25519 signatures for standalone installs, container volumes for state, cache and key file). TASK-26 is superseded; TASK-65's protocol question is answered with JSON lines for the first helpers (CBOR stays open for bulk data).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decision-10 on main absorbs decision-8 (done by TASK-165)
- [ ] #2 rules in docs/interop.md, docs/design/servers.md, naming-and-config.md and git-and-releases.md match the helpers as built
- [ ] #3 TASK-26 and TASK-65 updated
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01: decision-10 absorbs draft decision-8 of branch spike/go-rust-bridge (wasm2go only for a host that must be one binary and needs a core function; purego and wazero rejected); the docs changes of this task land with TASK-165 (interop.md, servers.md, naming-and-config.md, git-and-releases.md). What remains here is checking those documents against the helper implementation when it lands.
<!-- SECTION:NOTES:END -->
