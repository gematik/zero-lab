---
id: TASK-306
title: 'pdp authzserver: take its stores through its own interfaces, wired by zero-pdp'
status: To Do
assignee: []
created_date: '2026-11-14T10:36:00Z'
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
- [ ] #1 Config takes SessionStore, nonce.Record and dpop.ReplayCache, not kv.Store
- [ ] #2 pdp/authzserver does not import kv; cmd/zero-pdp builds the kv-backed implementations
- [ ] #3 NewServer refuses a configuration without the stores instead of creating in-memory ones, or the in-memory default is chosen by the command and logged
- [ ] #4 Shared-by-replicas behaviour (nonces, replay, sessions) keeps its tests
<!-- AC:END -->
