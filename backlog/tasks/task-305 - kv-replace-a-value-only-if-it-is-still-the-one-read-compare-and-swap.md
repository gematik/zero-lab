---
id: TASK-305
title: 'kv: replace a value only if it is still the one read (compare-and-swap)'
status: To Do
assignee: []
created_date: '2026-11-13T06:39:00Z'
labels: []
dependencies: []
ordinal: 320000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A caller that keeps state which must move forward atomically across replicas, such as the id of a session's current refresh token, has only SetIfAbsent and Take today. Add an optional operation that writes a new value only if the stored one equals the value the caller read, in memory and Postgres (one UPDATE with the old value in the WHERE clause), and through the sealed store (compare the stored sealed bytes, seal the new value). Wanted by zeta-pdp-go so that deleting or losing a record ends a session instead of permitting the reuse of a refresh token.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Of two replicas that replace the same value at once, exactly one succeeds
- [ ] #2 Works through NewSealed
<!-- AC:END -->
