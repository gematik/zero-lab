---
id: TASK-451
title: >-
  kv: Extend through any wrapper, not only a LocalKEK, so that an HSM wraps new
  keychain entries
status: To Do
assignee: []
created_date: '2026-11-27 12:30'
labels:
  - go
  - kv
  - keys
dependencies:
  - TASK-450
priority: medium
ordinal: 459000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-authserver-go TASK-141 (2026-11-27): kv.LocalKEK.Extend wraps a new entry with its own AES-256-GCM, so an entry under a key-encryption key in an HSM cannot be made with kv. zeta-admin-tools keychain add is to wrap through the HSM proxy's Encrypt (go/hsmproxy Wrap), with the entry's associated data as kv binds it now. A wrapper interface of kv's own, Wrap(ctx, kekID string, plaintext, associatedData []byte) (iv, ciphertext, tag []byte, err error), which LocalKEK satisfies and the HSM client by its method, and Extend taking it; the file format and what is bound stay as they are.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv.Extend(ctx, file, purpose, kekID, activeFrom, names, wrapper) makes the same entries as LocalKEK.Extend does today when the wrapper is a LocalKEK; files made before open unchanged
- [ ] #2 A test wraps through a fake wrapper that records kekID and associated data, and the entry opens through the matching unwrapper alone
<!-- AC:END -->
