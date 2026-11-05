---
id: TASK-93
title: 'Go deps: remove viper and echo'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T19:19:00Z'
labels:
  - go
  - deps
  - epa
  - pdp
dependencies: []
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: medium
ordinal: 91000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
viper and echo bring about 40 modules into epa and pdp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 flags plus os.Getenv in cmd/ instead of viper, http.ServeMux instead of echo
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
zero-epa: cobra flags instead of viper (its PDP_ environment prefix was undocumented and is gone), http.ServeMux and http.Server with a header timeout instead of echo; proxy names are limited to A-Z a-z 0-9 . _ - so they are safe in a route. pdp already had neither.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-epa uses cobra flags, http.ServeMux and an http.Server with a header timeout instead of viper and echo; pdp had neither.
<!-- SECTION:FINAL_SUMMARY:END -->
