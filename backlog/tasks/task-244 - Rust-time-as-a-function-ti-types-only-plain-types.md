---
id: TASK-244
title: 'Rust: time as a function, ti-types only plain types'
status: In Progress
assignee: []
created_date: '2026-11-07T15:52:00Z'
updated_date: '2026-11-07T19:01:00Z'
labels:
  - ti-types
  - architecture
dependencies: []
references:
  - docs/architecture.md
  - rust/docs/design.md
priority: medium
type: task
ordinal: 260000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: time enters every TI crate as a generic `impl Fn() -> Timestamp` (a struct that keeps it takes it as a type parameter); the Clock trait goes. A function lets a long operation (PIN entry, a login) read the time again, and lets ti-wasm pass Date.now(), where SystemTime panics (TASK-23). ti_types::Clock is used in ti-pki (config, time, ocsp, tsl_signature, validate, load), ti-cache (cache.rs), ti-connector-client (sds, connector) and ti-idpd (discovery, challenge). ti-types is meant to hold only the types several crates exchange; its optional clap integration belongs in ti-cli.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti_types::Clock and SystemClock are gone; every former user takes impl Fn() -> Timestamp, and Timestamp::now() is the system function hosts pass
- [ ] #2 ti-types holds Env, Tier and Timestamp only and depends on nothing but optional serde; the clap integration lives in ti-cli
- [ ] #3 just check fails if ti-types gains another dependency
- [ ] #4 rustls verifiers keep using the now rustls passes
<!-- AC:END -->
