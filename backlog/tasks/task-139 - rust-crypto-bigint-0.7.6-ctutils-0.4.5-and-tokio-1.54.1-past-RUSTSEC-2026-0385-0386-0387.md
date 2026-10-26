---
id: TASK-139
title: >-
  rust: crypto-bigint 0.7.6, ctutils 0.4.5 and tokio 1.54.1 past
  RUSTSEC-2026-0385/0386/0387
status: Done
assignee: []
created_date: 2026-10-24 08:41
updated_date: '2026-10-26T14:54:00Z'
labels:
  - rust
  - security
  - dependencies
milestone: m-0
dependencies: []
priority: high
ordinal: 149000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo deny fails on three new advisories: RUSTSEC-2026-0387 (crypto-bigint 0.7.5, timing variability), RUSTSEC-2026-0385 (ctutils, non-constant-time masks), RUSTSEC-2026-0386 (tokio AsyncFd unsound). Patch updates in Cargo.lock fix them; the vet exemptions move to the new versions, as for rustls-webpki.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cargo deny check advisories and cargo vet --locked pass
- [x] #2 just check passes
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
cargo update of crypto-bigint (0.7.6), ctutils (0.4.5) and tokio (1.54.1); their vet exemptions moved to the new versions. cargo deny, cargo vet --locked and just check pass.
<!-- SECTION:FINAL_SUMMARY:END -->
