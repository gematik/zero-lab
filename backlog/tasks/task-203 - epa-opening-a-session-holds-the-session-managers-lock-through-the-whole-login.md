---
id: TASK-203
title: >-
  epa: opening a session holds the session manager's lock through the whole
  login
status: Done
assignee: []
created_date: '2026-11-03T16:57:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - epa
dependencies: []
ordinal: 210000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
sessionManager.openSession holds sm.lock during OpenSession and Authorize, and GetSession's read lock waits for it. So while one provider logs in or times out, the proxy's other providers wait, also those with an open session. Found while making the first page's status parallel.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A slow or failing login at one provider does not delay another provider of the same proxy
- [x] #2 Concurrent callers for one provider still open only one session
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
A lock per provider: a login waits only for another at the same provider; an open session is returned without waiting. Tested with an injected login.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
A login waits only for another at the same provider; one session per provider still.
<!-- SECTION:FINAL_SUMMARY:END -->
