---
id: TASK-142
title: 'Repository: docs/conventions/agents.md owns the rules for agent-facing text'
status: To Do
assignee: []
created_date: 2026-10-26 11:07
updated_date: '2026-10-26T15:44:00Z'
labels:
  - docs
  - chore
milestone: m-0
dependencies: []
priority: medium
ordinal: 151000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Agent-facing text has no owning document: rust/ti-cli/AGENTS.md exists for ti only, PR #75 added a copy beside it, and repo-wide skills are planned. One convention document states: every CLI ships `<bin> agent` printing its embedded AGENTS.md as the only source; skills live in skills/ (usage) and .agents/skills/ (development) and are entry points only; the two skill modes (local with the binary, without it as in a web chat); and the agent rules for every tool, including the web-chat rules. See the decision on skills.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/conventions/agents.md exists and is linked from docs/README.md, CONTRIBUTING.md and CLAUDE.md
- [ ] #2 It states: one AGENTS.md per CLI, printed by <bin> agent, embedded in the binary
- [ ] #3 It states what a skill may contain (trigger, entry point, generated reference) and the split skills/ vs .agents/skills/
- [ ] #4 It states the mode without the binary: read the generated reference, run nothing, give the user commands to run locally
- [ ] #5 It states agent rules for every tool: never ask for or print real .kon, .p12, PINs or tokens; warn and do not repeat when one is pasted; PIN commands only on request; JSON output and exit codes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-9
<!-- SECTION:NOTES:END -->
