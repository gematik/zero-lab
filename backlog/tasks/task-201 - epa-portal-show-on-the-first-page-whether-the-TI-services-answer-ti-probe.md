---
id: TASK-201
title: 'epa portal: show on the first page whether the TI services answer (ti probe)'
status: Done
assignee: []
created_date: '2026-11-03T14:00:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - epa
dependencies: []
ordinal: 208000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The first page of the ePA middleware shows the VAU status per proxy, but not whether the TI services around it answer. Run ti probe for each environment the proxies use and show the result there.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A failing probe still returns its report: exit 1 with a report is a result, not an error
- [x] #2 A report of another schema version is refused
- [x] #3 Page loads share one run per environment and reuse its result for a minute, so a page cannot flood the TI services
- [x] #4 GET /api/probe answers per environment of the configured proxies; a failed run appears in that environment's entry, not as an HTTP error
- [x] #5 The first page shows each environment's services and says they answer, not that they are trustworthy
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti.Probe and ti.Prober in go/epa/ti, GET /api/probe in zero-epa, a card on the first page. Environments come from the configured proxies, so dev and ref on epa.t20r.cloud. esc() in portal.js now escapes quotes, because its results also go into attributes. The first page's card still needs a look in a browser.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The epa portal's first page shows whether the TI services answer, through ti probe.
<!-- SECTION:FINAL_SUMMARY:END -->
