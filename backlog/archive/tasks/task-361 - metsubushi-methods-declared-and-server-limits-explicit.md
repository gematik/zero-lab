---
id: TASK-361
title: 'metsubushi: methods declared and server limits explicit'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22 14:21'
labels: []
dependencies: []
priority: medium
ordinal: 376000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`metsubushi/main.go:55-69` registers routes without methods and sets only `ReadHeaderTimeout`. servers.md rule 28, "Method and path" and "Limits before work". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every route is `GET` (405 with `Allow` otherwise); the server sets `MaxHeaderBytes`, read, write and idle timeouts and shuts down on SIGTERM.
- [ ] #2 `wantsHTML` has a fuzz target.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: archived by the maintainer's decision: metsubushi is a smoke-test echo server.
<!-- SECTION:NOTES:END -->
