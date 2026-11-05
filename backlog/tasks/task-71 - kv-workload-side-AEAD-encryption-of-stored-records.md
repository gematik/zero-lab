---
id: TASK-71
title: 'kv: workload-side AEAD encryption of stored records'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-02T22:23:00Z'
labels:
  - go
  - kv
dependencies: []
references:
  - docs/design/servers.md
  - go/docs/design.md
priority: medium
ordinal: 69000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
kv stores records in plain text in Postgres (server rule 5).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 kv encrypts and authenticates every value in the workload (key, purpose and type as associated data) before it reaches the store; key rotation with key IDs
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
kv.NewSealed encrypts and authenticates every value in the workload, with a key per record and key IDs for rotation without restart.
<!-- SECTION:FINAL_SUMMARY:END -->
