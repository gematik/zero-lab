---
id: TASK-340
title: 'metsubushi: GET / echoes the request to programs'
status: In Progress
assignee: []
created_date: '2026-11-15T17:04:00Z'
labels: []
dependencies: []
ordinal: 355000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-336 made GET / answer JSON to programs, but with the pod info of /api/info. Behind the PEP the smoke test needs to see the request as it arrived, above all its headers (the identity the PEP adds). GET / answers programs with the echo of /api/anything: method, url, args, headers, origin, host, plus app.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GET / with curl's Accept returns the request's method, URL, query arguments and every header; a browser still gets the page; tested
<!-- AC:END -->
