---
id: TASK-381
title: >-
  kv: a keychain of wrapped entries (envelope encryption) and resealing under
  the current key
status: Done
assignee: []
created_date: '2026-11-18 20:02'
updated_date: '2026-11-18 20:02'
labels: []
dependencies: []
ordinal: 395000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
For zeta-pdp-go (its TASK-140), and server rule 19: the keys that seal records lie beside the data only wrapped under a key-encryption key that a key service holds. kv.Keychain reads the keychain file of the notification service of ZETA Guard (versioned entries, activeFrom, each a sealing key and a name key wrapped together, the entry ID as associated data), unwraps through kv.Unwrapper (an HSM or KMS adapter in the consumer; kv.LocalKEK for development), is a kv.Keys and hands out the name keys, current first. kv.Resealer on the store of NewSealed says which key sealed a record and seals it again under the current key with value and expiry unchanged, by compare-and-swap, so that records that outlive a key are taken along (rule 22).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A Keychain seals with the newest active entry, opens with every entry, follows its file and asks the key service only for new entries
- [x] #2 Reseal moves a record to the current key without changing its value or its end
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/kv/keychain.go: Keychain (ParseKeychain, LoadKeychain, NameKeys), Unwrapper, LocalKEK with NewEntry; go/kv/sealed.go: Resealer (SealedBy, Reseal). Tests for the current entry over time, the refusals of a file, following the file with a key service that fails, and resealing with its expiry kept. just check-changed passed. Not tagged: go/kv/v0.4.0 when the consumer is ready.
<!-- SECTION:FINAL_SUMMARY:END -->
