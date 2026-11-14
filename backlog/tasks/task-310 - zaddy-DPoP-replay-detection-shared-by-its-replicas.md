---
id: TASK-310
title: 'zaddy: DPoP replay detection shared by its replicas'
status: To Do
assignee: []
created_date: '2026-11-14T11:01:00Z'
labels: []
dependencies: []
ordinal: 325000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zaddy hands pep in-memory Replays (TASK-309 makes that choice explicit and logged), so each replica remembers only the proofs it accepted: a DPoP proof replayed to another replica within its lifetime (iat window plus leeway) is accepted there (RFC 9449 Section 11.1). Needs shared state for zaddy, which has none today: options are Caddy's storage module, the Postgres kv store the other servers use, or binding proofs to replica-local nonces so a replay at another replica fails the nonce check. Decide, then implement, as a dpop.Replays wired by zaddy (the host). servers.md rules on shared state and confidentiality apply (a store outside the workload is sealed).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The choice of shared state is recorded in the task or as a backlog decision
- [ ] #2 A proof accepted by one zaddy replica is refused by another within its lifetime, with a test
- [ ] #3 Without the shared state configured, zaddy logs that replay detection is per replica
<!-- AC:END -->
