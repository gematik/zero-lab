---
id: TASK-310
title: 'zaddy: DPoP replay detection shared by its replicas'
status: In Progress
assignee: []
created_date: '2026-11-14T11:01:00Z'
updated_date: '2026-11-17T06:36:00Z'
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
- [x] #1 The choice of shared state is recorded in the task or as a backlog decision
- [x] #2 A proof accepted by one zaddy replica is refused by another within its lifetime, with a test
- [x] #3 Without the shared state configured, zaddy logs that replay detection is per replica
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision (maintainer, 2026-11-17): follow Caddy best practice architecture. Caddy shares state between instances through its configured storage module (caddy.Context.Storage(), a certmagic.Storage: file system on a shared volume, or a storage plugin such as Redis, Consul or Postgres), the same way a Caddy cluster shares certificates and locks. zaddy keeps DPoP replays there, through a dpop.Replays implementation over certmagic.Storage (Lock, Exists, Store with the proof expiry; Delete when expired), instead of wiring an own kv store; without a shared storage it stays per replica and logs so (AC #3).

Built on fix/zaddy-shared-replays (cfe3211e, b1f5ccc4), merged into fix/elder-tasks: `pep { dpop_replays storage }` keeps accepted proofs in caddy.Context.Storage() under zaddy/dpop_replays/<sha256>, checked and written under the record lock (5 s bound, any storage error denies), swept each minute (≤1000 records). Explicit option, default memory with the per-replica warning, because Caddy cannot tell a local file_system path from a shared one. Tests TestRFC9449_11_1_* (two FileStorage replicas on one directory, concurrent proof accepted once, expiry), TestServersRule16_AStorageErrorRefusesTheProof, TestServersRule3_*.
<!-- SECTION:NOTES:END -->
