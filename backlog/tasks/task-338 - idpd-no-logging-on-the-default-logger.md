---
id: TASK-338
title: 'idpd: no logging on the default logger'
status: Done
assignee: []
created_date: '2026-11-15T14:41:00Z'
updated_date: '2026-11-16T20:38:00Z'
labels: []
dependencies: []
ordinal: 353000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the review of TASK-323/332 (2026-11-15): go/idpd logs through the default slog (authenticator.go ~336, ~341; client.go ~259; shared.go ~129), and shared.go ~174 logs the whole OP metadata at debug. go/docs/design.md section 2: a library logs only through a logger it was given. Same shape as TASK-332: a nil logger becomes a discard logger once at construction; or return the outcome.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 No non-test code in go/idpd calls the default slog; nothing logs a whole peer document
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The five default-logger calls in go/idpd are gone: SignWithSoftkeyPEM returns its parsing error through the signer, the debug lines (one of them the whole discovery document) are removed. Unreleased; goes out with the next idpd tag.
<!-- SECTION:FINAL_SUMMARY:END -->
