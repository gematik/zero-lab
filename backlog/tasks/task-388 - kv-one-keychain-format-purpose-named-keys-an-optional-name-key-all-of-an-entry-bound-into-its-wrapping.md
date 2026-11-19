---
id: TASK-388
title: >-
  kv: one keychain format: purpose, named keys, an optional name key, all of an
  entry bound into its wrapping
status: Done
assignee: []
created_date: '2026-11-18 22:01'
updated_date: '2026-11-18 22:01'
labels: []
dependencies: []
ordinal: 401000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
For zeta-pdp-go (its decision-15), still in the finding, so the format is changed in place and carries no version: the file is an object with a purpose, entries and the ids of revoked entries; an entry has id, version, activeFrom, kekId, the names of its keys and what is wrapped, a JSON object of the named keys. Everything the file says of an entry and the purpose are the associated data of the wrapping, where before only the id was. Every entry has the key that seals; one for names only when the names are to change, since that is what costs a service. WithKeychainCheck lets a consumer refuse a changed file, as one that lacks an entry still needed; Entries and Revoked say what a file holds. LocalKEK.Extend makes a file or its next entry. For the check: Marker.Marks, Resealer.SealedByKeys and Resealer.Mark. The format of the notification service is no longer read.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A changed, moved or re-timed entry is not unwrapped; a name key is in force from the newest entry that has one; a consumer's check keeps the keys in force
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/kv/keychain.go rewritten to the one format; kv.go, memory.go, postgres, sealed.go for the counts by mark and by key. Tests rewritten for it, with the refusals of every changed member. just check-changed passed, the Postgres tests against a local Postgres 18. Breaking for a consumer of v0.4.0's Keychain: ParseKeychain and LoadKeychain take a purpose, LocalKEK.NewEntry is Extend, the file is another.
<!-- SECTION:FINAL_SUMMARY:END -->
