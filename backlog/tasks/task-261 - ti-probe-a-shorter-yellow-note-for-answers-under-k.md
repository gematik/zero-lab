---
id: TASK-261
title: 'ti probe: a shorter, yellow note for answers under -k'
status: Done
assignee: []
created_date: '2026-11-07T19:32:00Z'
updated_date: '2026-11-07T19:40:00Z'
labels:
  - ti-cli
dependencies: []
priority: low
type: task
ordinal: 277000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer, 2026-11-07: the detail note 'TLS not checked (-k)' is too long and should alone be yellow; the answer itself keeps the colour of its verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the note reads 'TLS unchecked' and is the only yellow part of the row, in the live table and in the document output; JSON detail ends with it
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The detail of an answer under -k ends in 'TLS unchecked' (was 'TLS not checked (-k)'); only that note is yellow (style::WARN in the live table, a Warn status span in the document output), the rest keeps the verdict's colour. Test the_unchecked_note_alone_is_yellow; the -k integration test and AGENTS.md, ReleaseNotes adjusted. Full just check green before the merge.
<!-- SECTION:FINAL_SUMMARY:END -->
