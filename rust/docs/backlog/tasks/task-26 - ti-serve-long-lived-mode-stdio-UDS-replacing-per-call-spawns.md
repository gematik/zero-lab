---
id: TASK-26
title: 'ti serve: long-lived mode (stdio/UDS) replacing per-call spawns'
status: To Do
assignee: []
created_date: '2026-10-10 15:04'
updated_date: '2026-10-14 20:47'
labels:
  - ti-cli
  - integration
dependencies:
  - TASK-65
priority: low
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Runner-up to the per-call subprocess integration of doc-1 section 2. One ti process per consumer speaking the protocol TASK-65 decides (CBOR, protobuf or PKCS#11 semantics; docs/interop.md, RPC performance) over stdin/stdout (started with os/exec, dies with the parent) or over a Unix socket (--listen unix:PATH) for sidecar deployments and Java servers. Same schema-1 types as the CLI; keeps decoded identity, Konnektor session, TSL/OCSP cache and later an SSO token warm; ~100 us per call. Needs request multiplexing, cancellation, back-pressure and a protocol version. Trigger: a consumer that calls Rust per request (the ZETA client's DPoP proof per HTTP request), or a measured path a request waits for with a sustained rate above ~1/s or p99 above 200 ms per call. epa does not need it; its Go side is transport-agnostic so this is a new runner, not a rewrite.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti serve --stdio and --listen unix:PATH expose the identity, idpd and pki commands with the same JSON types as the CLI, versioned
- [ ] #2 a Go client (go/ticlient) and a Java client round-trip the same vectors as interop/
- [ ] #3 cancellation, back-pressure and child supervision are tested; a crash restarts the child and fails only in-flight calls
<!-- AC:END -->
