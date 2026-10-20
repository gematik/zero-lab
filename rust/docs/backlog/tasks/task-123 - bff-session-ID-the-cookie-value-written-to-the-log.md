---
id: TASK-123
title: 'bff: session ID (the cookie value) written to the log'
status: To Do
assignee: []
created_date: '2026-10-20 18:26'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 134000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/bff/session_manager_kv.go logs session.ID at Info on create and update ("session created", "session updated"). The ID is the session cookie's value, a bearer credential: whoever reads the logs can take over the session. Servers rule 5: logs, metrics and traces carry no personal data, tokens or secrets (docs/design/servers.md). Log a non-reversible reference instead (e.g. a truncated SHA-256 of the ID) or nothing; check the other bff and pdp log lines for the same pattern (state, codes, tokens).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no bff log line carries a session ID, state, code or token in clear; a test asserts it for session create and update
- [ ] #2 the same check done for pdp and pep, findings fixed or filed
<!-- AC:END -->
