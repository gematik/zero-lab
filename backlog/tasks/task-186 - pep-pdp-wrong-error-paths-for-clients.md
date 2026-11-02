---
id: TASK-186
title: 'pep, pdp: wrong error paths for clients'
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T23:09:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 196000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep: verifyAccessToken returns *Error while enforcers use errors.As with a value Error, which never matches, so an invalid token gets 500 under DPoP and 403 under Bearer rather than 401 invalid_token. pdp authorize.go: an upstream OP error redirects to authnSession.RedirectURI with authnSession.State, the AS's own callback, where the client needs authzSession's. Read from the code, not run (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A test per path proves the client gets the specified error
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed with requirement-named tests in the consolidation.
<!-- SECTION:FINAL_SUMMARY:END -->
