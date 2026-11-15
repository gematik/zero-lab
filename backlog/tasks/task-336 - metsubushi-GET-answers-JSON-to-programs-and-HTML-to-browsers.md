---
id: TASK-336
title: 'metsubushi: GET / answers JSON to programs and HTML to browsers'
status: In Progress
assignee: []
created_date: '2026-11-15T14:31:00Z'
updated_date: '2026-11-15T14:51:00Z'
labels: []
dependencies: []
ordinal: 351000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
metsubushi is the small app for smoke tests behind the PEP. GET / always returns the HTML page today; curl and test programs need the JSON of /api/info there. A request whose Accept names text/html (as browsers send) gets the page; any other gets the JSON. Responses carry Vary: Accept so caches keep the two apart.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET / with a browser's Accept returns the HTML page; with curl's Accept (*/*), none, or application/json it returns the info JSON; both carry Vary: Accept; tested
<!-- AC:END -->
