---
id: TASK-160
title: 'ti-connector-client: the service directory decides where the credentials go'
status: Done
assignee: []
created_date: '2026-11-01T13:35:00Z'
updated_date: '2026-11-01T16:08:00Z'
labels:
  - ti-connector-client
  - security
dependencies: []
references:
  - rust/ti-connector-client/src/soap.rs
  - rust/ti-connector-client/src/sds.rs
priority: high
ordinal: 171000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while fuzzing (TASK-47). Connector::call posts to the endpoint the service directory names, with the Authorization header of basic credentials, and nothing compares that endpoint with the .kon URL: without rewriteServiceEndpoints, connector.sds can name another host or a plain http endpoint, and the ureq transports do not set https_only. The directory comes over the pinned TLS connection or from the cache, which the crate treats as untrusted as the network. Read from the code, not yet proven by a test. rewriteServiceEndpoints: true is not affected since TASK-47: every endpoint is rewritten to the .kon origin or removed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A test proves that a directory naming another origin or plain http does not receive the credentials, or the maintainer decides why it may
- [x] #2 A real Konnektor whose directory names its own address behind NAT keeps a working path, with the hint to rewriteServiceEndpoints
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Rule: a call goes only to an endpoint with the scheme, host and port of the .kon url, or of its expectedHost under the url's port; ports normalized, what cannot be read exactly (user information, backslash) does not match. Checked in Connector::call, so nothing is sent; applies to every credential type, since documents go there too. connector config test fails at sds with the hint to rewriteServiceEndpoints. Fuzz target sds asserts that no request leaves the origin, whatever the directory names. Left: AC2, HITL with a real Konnektor.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
A Konnektor call goes only to the origin of the .kon url or its expectedHost; another endpoint is refused with DiscoveryError::ForeignEndpoint before anything is sent, and connector config test fails at sds with the hint to rewriteServiceEndpoints. HITL by the maintainer with a real Konnektor (infinity-ru): with rewriteServiceEndpoints=true, config test and get cards work. just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
