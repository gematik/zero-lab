---
id: TASK-104
title: >-
  Store: platform keyring wrappers (passphrase, Keychain/Secure Enclave, TPM,
  DPAPI)
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - keys
  - ti-cli
  - go
  - deps
dependencies:
  - TASK-103
references:
  - docs/design/keys.md
priority: low
ordinal: 110000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-103 ships the KeyWrapper abstraction with memory and key-file wrappers only. Hardware-bound keys are the normal case (docs/design/keys.md rules 2-3, 10): add platform wrappers, each as an adapter with its dependency approved first.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each wrapper registered in spec/store STORE-4xx and passes the keyring vectors
<!-- AC:END -->
