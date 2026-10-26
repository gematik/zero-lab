---
id: TASK-142
title: 'Repository: docs/conventions/agents.md owns the rules for agent-facing text'
status: Done
assignee: []
created_date: 2026-10-26 11:07
updated_date: '2026-10-26T18:03:00Z'
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
- [x] #1 docs/conventions/agents.md exists and is linked from docs/README.md, CONTRIBUTING.md and CLAUDE.md
- [x] #2 It states: one AGENTS.md per CLI, printed by <bin> agent, embedded in the binary
- [x] #3 It states what a skill may contain (trigger, entry point, generated reference) and the split skills/ vs .agents/skills/
- [x] #4 It states the mode without the binary: read the generated reference, run nothing, give the user commands to run locally
- [x] #5 It states agent rules for every tool: never ask for or print real .kon, .p12, PINs or tokens; warn and do not repeat when one is pasted; PIN commands only on request; JSON output and exit codes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-9
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
docs/conventions/agents.md states the rules of decision-9: one AGENTS.md per CLI, embedded and printed by <bin> agent, changed with the command it describes; skills as entry points (trigger, entry point, generated reference) in skills/ and .agents/skills/; the two modes, with and without the binary; the rules for agents with every tool (secrets by path only, placeholder .kon samples allowed, pasted secrets not repeated, PIN commands only on request, JSON and exit codes). Linked from docs/README.md, CONTRIBUTING.md and CLAUDE.md. Bringing ti's AGENTS.md onto it is TASK-148.
<!-- SECTION:FINAL_SUMMARY:END -->
