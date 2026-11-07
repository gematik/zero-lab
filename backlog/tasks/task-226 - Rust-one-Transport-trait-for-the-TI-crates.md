---
id: TASK-226
title: 'Rust: one Transport trait for the TI crates'
status: In Progress
assignee: []
created_date: '2026-11-06T06:43:00Z'
updated_date: '2026-11-07T10:57:00Z'
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
- [ ] #1 evaluated; one trait with adapters written once, or the reason the crates keep their own recorded
<!-- AC:END -->
