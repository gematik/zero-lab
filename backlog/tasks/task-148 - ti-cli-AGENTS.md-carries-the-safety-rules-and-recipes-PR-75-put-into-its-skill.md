---
id: TASK-148
title: >-
  ti-cli: AGENTS.md carries the safety rules and recipes PR #75 put into its
  skill
status: To Do
assignee: []
created_date: '2026-10-26T15:44:00Z'
labels:
  - docs
  - cli
milestone: m-0
dependencies:
  - TASK-142
priority: medium
type: docs
ordinal: 156000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PR #75 restates AGENTS.md in a skill and adds material AGENTS.md lacks: safety rules for .kon, .p12, PINs and tokens, and task recipes. The material belongs in AGENTS.md, the one source that ti agent prints (decision-9), so it reaches agents with the binary before any skill exists. The PR's drift shows what AGENTS.md must cover: the exit codes of output_exists, key_unsupported and store_no_keyring, the Bestandsnetze probe and the Konnektor fault hints. The PR is external: its text is input, not copied verbatim.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 AGENTS.md holds the PR's safety rules and recipes that it lacked, worded per docs/conventions/agents.md
- [ ] #2 AGENTS.md matches the binary: exit codes and error kinds, probe prod's Bestandsnetze, the Konnektor fault hints
- [ ] #3 Never asks an agent to print a real .kon, .p12, PIN or token; placeholder .kon samples are allowed
- [ ] #4 ti-cli Unreleased notes have an entry; just check is green
<!-- AC:END -->
