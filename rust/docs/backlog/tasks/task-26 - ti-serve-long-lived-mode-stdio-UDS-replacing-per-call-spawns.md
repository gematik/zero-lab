---
id: TASK-26
title: 'ti serve: long-lived mode (stdio/UDS) replacing per-call spawns'
status: Done
assignee: []
created_date: '2026-10-10 15:04'
updated_date: '2026-10-20 18:15'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Superseded by TASK-120 (2026-10-20): instead of one universal ti serve, per-group helpers with hand-picked functionality (ti-pki-helper, ti-idpd-helper first), over JSON lines, with a stdlib-only Go client go/tirpc. The TASK-116 spike measured the served variant at 1.3 ms per certificate check.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Not implemented: superseded by TASK-120, per-group helpers (ti-pki-helper, ti-idpd-helper) over JSON lines with the stdlib-only Go client go/tirpc instead of one universal ti serve. The criteria stay unticked; TASK-120 and its subtasks carry them.
<!-- SECTION:FINAL_SUMMARY:END -->
