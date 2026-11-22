---
id: TASK-358
title: 'epa: answers carry no input, internals or unchecked Aktensystem text'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22 14:21'
labels: []
dependencies: []
priority: medium
ordinal: 373000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`epa/proxy.go:580` echoes the insurant ID in an error; `proxy.go:570, 640, 679`, `insurants.go:122-136, 250, 265`, `status.go:91-99` and `cmd/proxy.go:218` return `err.Error()` with Aktensystem bodies and internals to the client; `parseHTTPError` repairs invalid UTF-8 and `responseJSON` writes it out (`session.go:316-336`, `insurants.go:74-75`); Aktensystem JSON is decoded without a `Content-Type` check. servers.md rule 28, "Output" (uniform errors) and "Outbound responses". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 error answers name a code and a fixed reason; upstream text stays in the log, bounded and free of control characters; invalid UTF-8 from an Aktensystem is refused, not replaced.
- [ ] #2 `FuzzParseHTTPError` asserts that the error does not contain the input's control characters.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps TASK-337 (rule 14 error texts), which fixes the error values; this task covers what the epa proxy answers to the client.

2026-11-22: archived by the maintainer's decision: zero-epa is not for production.
<!-- SECTION:NOTES:END -->
