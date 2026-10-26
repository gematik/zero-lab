---
id: TASK-144
title: >-
  Repository: skills/ with a zero-lab router skill and one entry-point skill per
  tool
status: To Do
assignee: []
created_date: '2026-10-26 11:07'
updated_date: '2026-10-26 11:07'
labels:
  - docs
  - chore
dependencies:
  - TASK-142
priority: low
ordinal: 153000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Usage skills for the CLIs, flat under skills/: zero-lab (routes a task to the tool), ti, zero-epa, zero-pdp, zero-caddy, … Each tool skill checks that the binary is installed, runs `<bin> agent` and follows it; without the binary (web chat) it reads references/AGENTS.md, generated from the tool's AGENTS.md, and runs nothing. Development skills go to .agents/skills/. A check keeps them honest.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 skills/zero-lab routes tasks to the tool skills and holds no tool knowledge
- [ ] #2 Each tool skill: narrow trigger on using the tool, two modes (binary present: <bin> agent; absent: generated references/AGENTS.md, no commands run)
- [ ] #3 references/AGENTS.md is generated from the tool's AGENTS.md and states the tool version it describes
- [ ] #4 just check fails when: a skill's frontmatter is invalid (name equals directory, description present and short), a tool skill names a binary without agent, a binary with agent has no skill, or a generated reference differs from its source
- [ ] #5 README and docs describe installing the skills without naming a vendor product
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-9
<!-- SECTION:NOTES:END -->
