---
id: TASK-307
title: >-
  pep/proxy: SessionStore and Revocations as pep interfaces, wired by
  zero-pep-proxy
status: Done
assignee: []
created_date: '2026-11-14T10:36:00Z'
updated_date: '2026-11-14T16:02:00Z'
labels: []
dependencies: []
ordinal: 322000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
proxy.Config takes kv.Store and kv.Bus (proxy.go), and the session store (session.go) and the cross-replica revocation set (revocation.go: publish over the bus, persist one key per sid, list them by prefix on start) are private code written against kv. The target pattern: pep defines a SessionStore and a Revocations interface in its own terms (load, save, delete a session; revoke, is revoked, follow revocations), and cmd/zero-pep-proxy wires the kv/Postgres implementations, sealed with kv.NewSealed. The library no longer imports kv; the private memRevoker and busRevoker become implementations of Revocations and are named after it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Config takes pep SessionStore and Revocations interfaces, not kv.Store and kv.Bus
- [x] #2 pep/proxy does not import kv; the kv-backed implementations live with the wiring in cmd/zero-pep-proxy
- [x] #3 Revocation across replicas and sessions at rest keep their tests, including the Postgres-gated ones
- [x] #4 Revocations is the one name for the interface and its implementations (no Revoker, revocation store or cache)
- [ ] #5 Revocations methods take a context and return an error; an error means revoked (deny), with a test; entries carry an until so they expire with the session
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
proxy.Config takes SessionStore and Revocations (ctx and error on every method; a failing revocation check denies; entries expire with the snapshot TTL) instead of kv.Store and kv.Bus. kv-backed versions live in cmd/zero-pep-proxy with unchanged keys, sealing and channel; the proxy refuses to start when it cannot follow revocations (maintainer confirmed). Sign-out runs to the end when the browser cancels the request, with a test. Gateway snapshot routes not checking revocations predates this: TASK-311. Branch refactor/module-stores.
<!-- SECTION:FINAL_SUMMARY:END -->
