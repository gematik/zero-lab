---
id: TASK-145
title: 'Release: skill ZIP per tool as a release asset'
status: To Do
assignee: []
created_date: '2026-10-26 11:07'
updated_date: '2026-10-26 11:07'
labels:
  - release
  - chore
dependencies:
  - TASK-144
priority: low
ordinal: 154000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Web chats install a skill by upload, not from git. The release of a tool regenerates its skill's references/AGENTS.md from the released binary and attaches skills/<tool> as a ZIP to the GitHub release, so the uploaded skill describes exactly that version.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just release regenerates the tool's references/AGENTS.md from the released source
- [ ] #2 just publish attaches <tool>-skill.zip to the GitHub release, listed in SHA256SUMS
- [ ] #3 rust/docs/development.md (and the Go guide once Go tools ship skills) describe the step
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-9
<!-- SECTION:NOTES:END -->
