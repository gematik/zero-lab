---
id: TASK-13
title: 'ureq: custom TLS verifier without the unversioned API (watch)'
status: To Do
assignee: []
created_date: 2026-10-09 13:55
updated_date: '2026-11-07T16:39:00Z'
labels:
  - ti-connector-client
  - ti-tls
  - deps
  - watch
dependencies:
  - TASK-249
priority: low
ordinal: 31000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-connector-client's and ti-tls's ureq adapters use ureq's semver-exempt unversioned transport API (ureq pinned ~3.5) because TlsConfig takes no certificate verifier or rustls ClientConfig: a Konnektor needs Go's semantics (.kon pins, expectedHost as SNI), and ti-tls's profiles need their own verifier. ureq main (after 3.5.1) still offers none. Decision-15 moves both adapters into the host library ti-client (TASK-249), so no published crate carries the pin; this task watches upstream for a way off the unversioned API.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ureq accepts a custom verifier or rustls ClientConfig and ti-client's transports use it instead of the unversioned API, or the task stays parked with the upstream state noted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-07: the bump to ureq 3.5.1 waits on branch chore/ureq-3.5 (TransportAdapter::new takes the connection's clock, details.current_time): it changes the workspace Cargo.toml, which jwz's browser stamp hashes, and jwz is stamped again only after its pending tasks. Upstream checked: CHANGELOG to 3.5.1 and src/tls/mod.rs on main have no verifier hook.
<!-- SECTION:NOTES:END -->
