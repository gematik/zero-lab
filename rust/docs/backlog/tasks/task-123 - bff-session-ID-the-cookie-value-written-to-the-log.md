---
id: TASK-123
title: 'bff: session ID (the cookie value) written to the log'
status: Done
assignee: []
created_date: '2026-10-20 18:26'
updated_date: '2026-10-20 18:29'
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
- [x] #1 no bff log line carries a session ID, state, code or token in clear; a test asserts it for session create and update
- [x] #2 the same check done for pdp and pep, findings fixed or filed
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
bff: session ID (the cookie value) and state appear in logs and in not-found errors only as the first 8 bytes of their SHA-256 (logRef); TestServersRule5_SessionIDAndStateNeverLogged covers create, update, delete and both lookups and fails on the old code (4 leaks). pdp: the token endpoint no longer logs the authorization code, the session dump (%+v) or the issued tokens; the OP session (state, nonce, PKCE verifier) is logged by ID and issuer only; zero-pdp no longer dumps its config at Debug. pep: no raw JWT on a parse failure; login start logs the authorization endpoint without its query (state, nonce, challenge, request_uri). pep session IDs and pdp session IDs (the jti) stay in logs: they are identifiers, the pep cookie carries a separate token.
<!-- SECTION:FINAL_SUMMARY:END -->
