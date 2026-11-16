---
id: TASK-321
title: 'Servers: zero-pep-proxy, zero-caddy and zero-epa checked against rule 28'
status: Done
assignee: []
created_date: '2026-11-14T21:07:00Z'
updated_date: '2026-11-16T22:52:00Z'
labels:
  - servers
  - go
dependencies: []
ordinal: 336000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 28 (every HTTP message is checked before the logic sees it) is new; the existing servers have not been checked against it: method allowlists, canonical paths, repeated and unknown parameters, Content-Type and body limits, strict JSON, Host, cookies, redirects, uniform errors, outbound responses, and fuzz targets per handler. Each gap found becomes its own task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each server is checked against rule 28 and every gap is a task
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-17: zero-pdp left out of scope; zeta-pdp-go replaces it.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy, zero-caddy, zero-epa and metsubushi checked against rule 28 (audit in the session scratchpad, summarised in the tasks). Every gap is a task: TASK-350 to 361; high: 350 (gateway route matching on non-canonical paths, verified) and 355 (epa: chunked request loses its framing inside the VAU, request smuggling). TASK-358 overlaps TASK-337 on epa error texts. Outside rule 28: logout CSRF via GET /oauth2/sign_out (TASK-259) and zero-epa listening without authentication.
<!-- SECTION:FINAL_SUMMARY:END -->
