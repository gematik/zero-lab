---
id: TASK-390
title: 'pep/proxy: a login state is taken atomically'
status: Done
assignee: []
created_date: '2026-11-19 08:47'
updated_date: '2026-11-22 14:54'
labels:
  - pep-proxy
  - security
  - oauth
dependencies: []
references:
  - docs/design/servers.md
priority: medium
ordinal: 403000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
handleCallback resolves a session by its state (sessionManager.byState) and then deletes the state index (deleteState): two store calls. Two callbacks with the same state that arrive together can both resolve it before either deletes it, and both go on to redeem a code. Since TASK-369 the state is consumed on first use, but not atomically. servers.md rule 11 asks that single-use values are consumed atomically (an atomic take such as kv.Store.Take), so two replicas can never both accept the same value. SessionStore (go/pep/proxy/session.go) has SessionID and DeleteState and no take; adding one changes the exported interface and its kv implementation. Found while working TASK-369 (2026-11-19).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The state of a login is taken in one store operation; of two callbacks with the same state at most one finds a session, on one replica and across two
- [x] #2 A test runs concurrent callbacks against the memory store and the kv store and counts one redeemed code
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
SessionStore's SessionID became TakeSessionID: the index from a login state to its session is read and removed in one operation (kv's atomic Take in zero-pep-proxy's kvSessions), and sessionManager.takeByState replaces byState plus deleteState in the callback. Breaking for implementers of proxy.SessionStore. Tests: TestServerRule11_OfConcurrentCallbacksWithOneStateOneRedeemsTheCode (32 concurrent callbacks, one and two replicas over one store, exactly one Complete), TestServerRule11_TwoReplicasTakeALoginStateOnceOverTheKVStore (kv memory store shared by two replicas), both green under -race; the Postgres Take is covered by kv's own gated TestPostgres_TakeSingleUseConcurrent.
<!-- SECTION:FINAL_SUMMARY:END -->
