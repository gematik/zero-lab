---
id: TASK-308
title: 'zaddy: load its DPoP nonce keys itself instead of importing kv'
status: In Progress
assignee: []
created_date: '2026-11-14T10:36:00Z'
updated_date: '2026-11-14T10:53:00Z'
labels: []
dependencies: []
ordinal: 323000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zaddy imports kv only for kv.LoadKeyring, to get the keys of its DPoP nonces (zaddy.go dpopNonces); it stores nothing. A module wires its own needs: zaddy reads its key file itself and hands nonce a nonce.Keys. The keyring stays in kv, where kv.NewSealed and the commands that seal their stores use it. Caddy provisions the module again on a config reload, so zaddy reads the file at provisioning and does not follow it. The file keeps the keyring's format (<id> <base64 of 32 bytes> per line, the first current, # comments; or one bare key), so one key file format serves every component.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zaddy loads its DPoP nonce key file itself, in the keyring's format, and no longer imports kv
- [ ] #2 A malformed file, a key of the wrong size or a duplicate ID refuses provisioning, with tests
- [ ] #3 kv's keyring is unchanged
<!-- AC:END -->
