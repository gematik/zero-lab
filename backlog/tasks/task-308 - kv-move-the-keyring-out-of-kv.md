---
id: TASK-308
title: 'kv: move the keyring out of kv'
status: To Do
assignee: []
created_date: '2026-11-14T10:36:00Z'
labels: []
dependencies: []
ordinal: 323000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
kv.Keyring (keyring.go: LoadKeyring, ParseKeyring, file following) loads key files; it is not storage. zaddy imports kv only for it, to get the keys of its DPoP nonces (zaddy.go dpopNonces). Move it to a package about keys (in nonce, or a small keys module both kv.NewSealed and nonce consume through their own Keys interfaces), so that a module that needs keys does not depend on the store.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The keyring lives outside kv; kv.NewSealed and nonce take it through their Keys interfaces
- [ ] #2 zaddy no longer imports kv
- [ ] #3 The keyring file format and its tests are unchanged
<!-- AC:END -->
