---
id: TASK-12
title: 'rsa 0.10 release: leave the release candidate'
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - deps
  - watch
dependencies: []
references:
  - Cargo.toml
  - deny.toml
priority: low
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rsa is pinned to =0.10.0-rc.18, the only line on the current RustCrypto stack (Known compromises). When 0.10 is released, switch to "0.10"; drop the RUSTSEC-2023-0071 ignore in deny.toml and .cargo/audit.toml once a patched rsa exists (ti-pki only verifies on public data, so the Marvin attack does not apply).
<!-- SECTION:DESCRIPTION:END -->
