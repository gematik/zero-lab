---
id: TASK-273
title: 'jwz: errors carry the host''s cause; a public Header constructor'
status: In Progress
assignee: []
created_date: '2026-11-08T13:47:00Z'
updated_date: '2026-11-08T14:01:00Z'
labels:
  - jwz
  - api
milestone: m-1
dependencies:
  - TASK-251
priority: medium
ordinal: 289000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-251 (RemoteJwks, the first fetching KeyResolver). jwz::Error holds only a static context, so a resolver's or chain validator's real cause (HTTP status, TLS, DNS, cache store) cannot reach the caller of verify_with; RemoteJwks keeps it in a Mutex beside the error, which races under concurrent use. And a host cannot construct a Header, so a resolver can only be called through a parsed JWS (tests, pre-warming a kid). Maintainer's decisions (2026-11-08): jwz::Error gets an optional cause from the host, reachable through core::error::Error::source and never part of Display (jwz's own messages stay free of input data); Error stops being Copy (jwz 0.2.0 is breaking anyway); Header gets a public constructor from JSON. Kept as they are, also decided: AsyncKeyResolver's future stays without Send (decision-15, as the async signer and x5c traits); no key matching and a bad signature both stay VerificationFailed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 jwz::Error::with_source attaches a host cause (Send + Sync + 'static); source() returns it; Display, code() and context() are unchanged; equality compares code and context
- [x] #2 Header has a public constructor from JSON that refuses what Header::decode refuses (duplicate members, not an object)
- [x] #3 ti-client's RemoteJwks passes its cause through the error and drops last_error(); tests prove the cause reaches the caller of verify_with
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Error holds an optional Arc<dyn Error + Send + Sync> cause (with_source); source() returns it, Display/code/context unchanged, PartialEq compares code and context. Error is no longer Copy: local errors reused within a function became function-local consts (Error::new is const fn), two with a runtime name became closures; signature_error clones. Header::parse builds a header from JSON (duplicates and non-objects refused). RemoteJwks passes FetchError as the source and drops last_error(); its test reads the cause from verify_with's error. ti-client's identity card signer still keeps the Konnektor's error beside the jwz error (take_error), which could use with_source too: not changed here.
<!-- SECTION:NOTES:END -->
