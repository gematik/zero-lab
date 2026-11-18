---
id: TASK-301
title: Rate limiter for servers
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-18T20:24:00Z'
labels:
  - go
  - servers
  - parked
dependencies: []
ordinal: 317000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/design/servers.md asks servers for rate limits and no module provides one. zeta-pdp-go builds one on kv.Store for its endpoints (its TASK-46, gemSpec_ZETA A_26668-02 with the x-rate-limit headers); a shared one could take its place. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A decision whether the limiter is a module here; if so, one that counts across replicas on kv.Store
- [ ] #2 The limiter takes its settings (limits, windows, how a client is keyed) as an httpguard struct passed by value, and its counter store as an interface; it reads no environment, flag or file. The server host fills the struct from its own env vars or config file and supplies the store (for example a kv.Store adapter), so httpguard stays stdlib-only
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-18: the shared rate limiter goes into go/httpguard, the stdlib-only module TASK-360 creates for the rule 28 request checks (maintainer).

2026-11-18: configuration rule (maintainer): only the host reads env vars or config files; the core library takes everything by value. httpguard has no configuration today beyond the names passed to Host.
<!-- SECTION:NOTES:END -->
