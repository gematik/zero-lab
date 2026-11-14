---
id: TASK-306
title: 'pdp authzserver: take its stores through its own interfaces, wired by zero-pdp'
status: Done
assignee: []
created_date: '2026-11-14T10:36:00Z'
updated_date: '2026-11-14T16:02:00Z'
labels: []
dependencies: []
ordinal: 321000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
authzserver.Config takes a raw kv.Store (config.go Store), and NewServer builds the session store, the nonce record and the DPoP replay cache from it, falling back to kv.NewMemory inside the library (server.go). The target pattern: a module defines its store in its own terms, and the host (command, image) wires the backend. authzserver already has SessionStore; nonce has nonce.Record and dpop has dpop.ReplayCache. Config takes those three instead of kv.Store, the kv-backed implementations move next to the wiring in cmd/zero-pdp, and the library no longer imports kv. Tests use in-memory implementations of the interfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Config takes SessionStore, nonce.Record and dpop.ReplayCache, not kv.Store
- [x] #2 pdp/authzserver does not import kv; cmd/zero-pdp builds the kv-backed implementations
- [x] #3 NewServer refuses a configuration without the stores instead of creating in-memory ones, or the in-memory default is chosen by the command and logged
- [x] #4 Shared-by-replicas behaviour (nonces, replay, sessions) keeps its tests
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
authzserver.Config takes Sessions, NonceRedemptions and Replays instead of kv.Store; New refuses a configuration without them or NonceKeys. The kv-backed session store moved to cmd/zero-pdp, which wires all stores over one (memory or sealed Postgres) store; authzserver imports no kv. A test proves the store only receives refresh token hashes. Dead NewFromConfigFile: TASK-312. Branch refactor/module-stores.
<!-- SECTION:FINAL_SUMMARY:END -->
