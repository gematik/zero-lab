---
id: TASK-252
title: 'Rust: a test implementation that is not Send for every host trait'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T19:01:00Z'
labels:
  - architecture
  - tests
  - wasm
dependencies: []
references:
  - docs/architecture.md
priority: low
type: task
ordinal: 268000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the traits product clients define are async without a Send bound, so a browser host (JS fetch, not Send) can implement them. Nothing proves that the clients keep working with a host that is not Send; a Send-only assumption in client code (a spawned future, a Send bound added by accident) would break wasm silently, since ti-wasm uses few clients today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each async host trait (soap::Transport, load::Transport, Fetch, CacheStore, idpd's and the directory's transports, the directory's token trait) has a test implementation holding an Rc, and a test drives the client through it
<!-- AC:END -->
