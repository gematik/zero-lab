---
id: TASK-178
title: 'bff, pdp, pep: session records reach the kv store unencrypted'
status: To Do
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T15:43:00Z'
labels:
  - go
  - security
dependencies:
  - TASK-71
priority: high
ordinal: 188000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/bff session_manager_kv.go and go/pdp authzserver/session_store_kv.go marshal whole sessions to kv as plain JSON, including access and refresh tokens, the PKCE verifier and authorization codes; go/pep seals only when PEP_SESSION_STORE_KEY_PATH is set and starts without it. servers.md rule 5 says the store sees ciphertext only, rule 17 that production refuses insecure configuration. pdp's comment 'a kv reader gets hashes' is not true for the whole record. Found by gosec G117 (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The store sees ciphertext only in all three, production refuses to start without the key, and the nolint lines naming this task are gone
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-71 covers kv encryption in general; this one names the session records and the production refusal.
<!-- SECTION:NOTES:END -->
