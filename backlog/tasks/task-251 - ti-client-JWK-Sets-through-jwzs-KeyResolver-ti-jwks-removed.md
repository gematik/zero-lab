---
id: TASK-251
title: 'ti-client: JWK Sets through jwz''s KeyResolver, ti-jwks removed'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-08T12:06:00Z'
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
- [ ] #1 ti-client has RemoteJwks implementing jwz's KeyResolver with each rule above, each proven by a test named after its source (RFC 7517, RFC 9111, RFC 9110 sections)
- [ ] #2 ti-jwks is removed from the workspace, its fuzz targets and traceability entries moved or removed with the reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer (2026-11-08): done before jwz 0.2.0 is released, as the first real user of KeyResolver; ti-jwks's removal is a manifest change that precedes the release's single restamp (TASK-272).
<!-- SECTION:NOTES:END -->
