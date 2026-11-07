---
id: TASK-244
title: 'Rust: time as a function, ti-types only plain types'
status: In Progress
assignee: []
created_date: '2026-11-07T15:52:00Z'
updated_date: '2026-11-07T19:14:00Z'
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
- [x] #1 ti_types::Clock and SystemClock are gone; every former user takes impl Fn() -> Timestamp, and Timestamp::now() is the system function hosts pass
- [x] #2 ti-types holds Env, Tier and Timestamp only and depends on nothing but optional serde; the clap integration lives in ti-cli
- [x] #3 just check fails if ti-types gains another dependency
- [x] #4 rustls verifiers keep using the now rustls passes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Time is a function: ti-cache Cache<S, N: Fn() -> Timestamp> (Cache::clock became Cache::now), ti-pki HttpLoader, CachingLoader, Reloader, TrustStoreHandle and OcspChecker take N the same way; ti-connector-client and ti-jwks follow through Cache. ti_types::Clock/SystemClock removed; Timestamp::now (std, not on wasm32-unknown-unknown) is what hosts pass. ti-pki keeps FixedClock (test-util) as a settable time with an inherent now(), passed as || clock.now(). ti-tls verifiers unchanged: they take the now rustls passes. jwz untouched; ti-idpd/ti-cli keep passing jwz FixedClock/SystemClock values (now: u64 parameters, never a ti Clock). The clap feature of ti-types had no user (ti-cli parses --env with its own Environment ValueEnum and FromStr for probe targets), so it is removed with nothing to move. ti-cli's crate::now() duplicate replaced by Timestamp::now(). just core-deps fails if ti-types gains a normal dependency other than serde, or serde stops being optional.
<!-- SECTION:NOTES:END -->
