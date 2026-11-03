---
id: TASK-155
title: 'rust: crypto-bigint 0.7.6 was yanked, update to 0.7.10'
status: Done
assignee: []
created_date: '2026-10-28T19:01:00Z'
updated_date: '2026-10-28T19:02:00Z'
labels:
  - rust
  - deps
  - security
milestone: m-0
dependencies: []
priority: high
type: bug
ordinal: 163000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo deny fails just check: crypto-bigint 0.7.6 (from TASK-139) is yanked on crates.io. cargo update -p crypto-bigint moves it to 0.7.10 and ctutils to 0.4.6; their cargo vet exemptions move along, as at earlier bumps (TASK-59 reduces exemptions).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Cargo.lock at crypto-bigint 0.7.10 and ctutils 0.4.6; cargo vet and cargo deny green; ti-cli Unreleased notes name it
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
cargo update -p crypto-bigint: 0.7.6 (yanked) → 0.7.10, ctutils 0.4.5 → 0.4.6; their cargo vet exemptions moved to the new versions; the ti-cli security note names them. cargo vet, cargo deny and just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
