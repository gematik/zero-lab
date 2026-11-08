---
id: TASK-251
title: 'ti-client: JWK Sets through jwz''s KeyResolver, ti-jwks removed'
status: Done
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-08T17:37:00Z'
labels:
  - ti-client
  - ti-jwks
  - architecture
milestone: m-1
dependencies:
  - TASK-243
references:
  - rust/ti-jwks/src/lib.rs
priority: low
type: task
ordinal: 267000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: a client verifies tokens with jwz::jwk::KeyResolver; ti-client implements it over HTTP. ti-jwks (rust/ti-jwks) is used by no crate today and goes; its rules stay: https only, a redirect is an error, body and key-count limits, freshness from Cache-Control clamped to 5 minutes..24 hours (1 hour without), revalidation by ETag or Last-Modified, no stale set when the origin fails, a refetch for an unknown kid at most once a minute, a fetched set replaces the old one whole.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-client has RemoteJwks implementing jwz's KeyResolver with each rule above, each proven by a test named after its source (RFC 7517, RFC 9111, RFC 9110 sections)
- [x] #2 ti-jwks is removed from the workspace, its fuzz targets and traceability entries moved or removed with the reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer (2026-11-08): done before jwz 0.2.0 is released, as the first real user of KeyResolver; ti-jwks's removal is a manifest change that precedes the release's single restamp (TASK-272).

Implemented (2026-11-08): ti_client::jwks::RemoteJwks<S, N, T = UreqTransport> implements jwz KeyResolver and AsyncKeyResolver (ready future). new(url, &Net, store, now) uses http::idp_agent (web profile, no redirect followed, statuses not errors); with_transport(url, transport, store, now) takes a jwks::Transport (one blocking GET returning status, headers, body), the https check applies to both. Every ti-jwks rule kept; FetchError is the rich error, mapped to ErrorCode::KeyUnavailable with a static context per cause, the cause kept in last_error() because jwz::Error carries only &'static str. An empty candidate list (no key fits) is Ok(vec![]) and jwz answers VerificationFailed. Rule tests over a scripted transport with a moved clock; loopback TLS tests (Konnektor test CA from ti-connector-client/tests/tls, name pinned to konnektor.test, over http::redirectless_agent = idp_agent's settings with another rustls config) for redirect, http refused unconnected, the body limit on the ureq path and end-to-end verify_with accept/refuse. ti-jwks removed: no fuzz targets existed (its parsing is jwz's JwkSet::parse, fuzzed in jwz); traceability entries carried over to ti-client's table under the same RFC sections; the core-deps HTTP-client check for ti-jwks removed with its subject.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti_client::jwks::RemoteJwks implements KeyResolver over ti-client's HTTP agent and a ti-cache store with every rule of ti-jwks (https only, redirect an error, 64 KiB/100 keys, Cache-Control 5 min-24 h, revalidation, no stale set, unknown kid at most once a minute), tested over a scripted transport and real HTTPS loopback; ti-jwks removed.
<!-- SECTION:FINAL_SUMMARY:END -->
