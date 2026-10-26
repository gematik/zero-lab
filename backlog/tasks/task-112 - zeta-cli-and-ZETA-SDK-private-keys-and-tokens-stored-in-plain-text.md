---
id: TASK-112
title: 'zeta-cli and ZETA SDK: private keys and tokens stored in plain text'
status: To Do
assignee: []
created_date: '2026-10-15 17:51'
labels:
  - zeta
  - security
  - keys
dependencies: []
references:
  - docs/design/keys.md
priority: high
ordinal: 118000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zeta-cli JsonFileStorage (cli/storage/JsonFileStorage.kt:47) writes DPoP and client private keys and access/refresh tokens in clear JSON (0600, no cross-process lock). In the SDK, SecureSdkStorage routes to the keyring only keys ending _token or containing private_key, but ExtendedStorage has already hashed or prefixed keys, so tokens (at:, rt:) never reach the keyring; iOS storage is in memory only; ExtendedStorage keys are a truncated String.hashCode (collisions). docs/design/keys.md rule 1 (no key bytes at rest), decision-7. Fix lives in the zeta repositories; tracked here until handed over.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 issue raised with the zeta-cli and ZETA SDK owners with these findings
<!-- AC:END -->
