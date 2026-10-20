---
id: TASK-119
title: 'ti: HITL of the sealed comfort ID with a real Konnektor'
status: To Do
assignee: []
created_date: '2026-10-20 11:46'
labels:
  - ti-cli
  - store
  - hitl
dependencies: []
priority: medium
ordinal: 122000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Split from TASK-103.5 (AC 5) when the store iteration was wrapped up: the comfort signature flow against a real Konnektor and HBA in a throwaway profile (TI_STATE_DIR, TI_CACHE_DIR, TI_STORE_KEK_PATH): connector comfort activate, sign without PIN, ti store ls shows the comfort record sealed, ti store doctor --deep opens it, comfort deactivate removes it, profile delete. Covered so far only against the fake Konnektor (tests/connector.rs).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 comfort activate, a PIN-less sign and deactivate work against a real Konnektor with the ID sealed in state.db, proven by the maintainer
<!-- AC:END -->
