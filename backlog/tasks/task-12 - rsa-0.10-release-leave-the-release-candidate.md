---
id: TASK-12
title: 'rsa 0.10 release: leave the release candidate'
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
updated_date: '2026-10-20 16:51'
labels:
  - watch
dependencies: []
references:
  - Cargo.toml
  - deny.toml
priority: low
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rsa is pinned to =0.10.0-rc.19 with pkcs1 0.8.0-rc.5 (TASK-117), still a release candidate and the only line on the current RustCrypto stack (Known compromises). When 0.10 is released, switch to "0.10"; drop the RUSTSEC-2023-0071 ignore in deny.toml and .cargo/audit.toml once a patched rsa exists (ti-pki only verifies on public data, so the Marvin attack does not apply).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Also blocks just audit's semver step: rebuilding the ti-cli 0.2.0 baseline fails to compile against rsa 0.10.0-rc.18 (seen at the 0.3.0 release, 2026-10-10); TASK-34 needs that step working or skipped.
<!-- SECTION:NOTES:END -->
