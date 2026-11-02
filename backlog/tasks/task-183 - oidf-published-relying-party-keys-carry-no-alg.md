---
id: TASK-183
title: 'oidf: published relying party keys carry no alg'
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T21:44:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 193000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
relying_party.go passes jwa.ES256 and jwa.ECDH_ES as functions to publicKey.Set, which always fails, and the error was ignored, so the published JWKs have no alg. Fixing it changes the JWKS of registered relying parties, so it needs checking against the federation. Found by errcheck (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The key's alg is published or the call removed, the error is returned, and the nolint lines naming this task are gone
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Relying party keys publish alg; the error is returned.
<!-- SECTION:FINAL_SUMMARY:END -->
