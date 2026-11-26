---
id: TASK-443
title: 'zaddy: session revocations again, without a database'
status: To Do
assignee: []
created_date: '2026-11-26T19:54:00Z'
labels:
  - go
  - zaddy
  - security
dependencies: []
priority: medium
ordinal: 452000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
On 2026-11-26 the maintainer had zaddy's database taken out, revocations included (zaddy reached zero-pep-proxy's Postgres through revocations_database_url, TASK-313, and with WithMigrate could change its schema). The convention: libraries define business interfaces, hosts implement them and map them, for instance to kv; zaddy, an edge on the public port, uses Caddy's built-in means for shared state (its storage holds the DPoP replays, TASK-310) and holds no credentials of another service's database. Since the removal a policy with a SessionCookie enforcer is refused at provisioning: without revocations a snapshot of zero-pep-proxy would admit a signed-out session for its lifetime (8 h by default), the defect TASK-313 closed. Ways, weighed on 2026-11-26: (A) zero-pep-proxy serves its revocations as an endpoint (those after a cursor; its kv Feed is the source) and zaddy follows it over HTTP into a local set, implementing pep.SessionRevocations; no database, no driver, mTLS between the two (servers.md rule 29); (B) forward_auth to zero-pep-proxy's /oauth2/auth on every request, which works today and costs the round trip the snapshot saves; (C) Caddy's storage, which does not fit: the writer is not a Caddy, and it has neither expiry nor notification; (D) a short snapshot lifetime as the only bound. Recommendation of 2026-11-26: A.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zaddy admits a SessionCookie snapshot only while its session is not revoked, with revocations from zero-pep-proxy and without a database or a database driver in its module graph
- [ ] #2 A revocation at zero-pep-proxy reaches every zaddy replica within a stated bound, shown by a test across processes; a zaddy that cannot follow refuses snapshots after a stated time (rule 17)
- [ ] #3 The channel between them is protected as rule 29 has it, and the endpoint names no session to whoever is not allowed to follow
<!-- AC:END -->
