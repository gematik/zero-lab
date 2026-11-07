---
id: TASK-226
title: 'Rust: one Transport trait for the TI crates'
status: Done
assignee: []
created_date: '2026-11-06T06:43:00Z'
updated_date: '2026-11-07T15:54:00Z'
labels:
  - deps
  - architecture
dependencies: []
priority: low
ordinal: 233000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-pki (load::Transport), ti-idpd (http::Transport) and ti-jwks each define an HTTP transport trait and adapters. One trait in a shared low crate would let one ureq adapter (and any host's) serve all. Split out of TASK-18.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 evaluated; one trait with adapters written once, or the reason the crates keep their own recorded
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Evaluated with TASK-227; recorded as decision-15. No shared transport crate: each product client keeps its own narrow async trait (no Send, one variant), and ti-client implements them all over one ureq agent per TLS profile; the ureq adapters leave the product crates (TASK-249). ti-idpd's synchronous transport becomes async (TASK-245); ti-jwks goes (TASK-251).
<!-- SECTION:FINAL_SUMMARY:END -->
