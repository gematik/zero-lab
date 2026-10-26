---
id: TASK-141
title: 'ti-cli: thin agent skill that defers to ti agent (PR #75)'
status: To Do
assignee: []
created_date: '2026-10-26 10:26'
updated_date: '2026-10-26 11:07'
labels:
  - ti-cli
  - docs
dependencies:
  - TASK-144
priority: low
ordinal: 150000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PR #75 (external) adds rust/ti-cli/skills/ti-cli with SKILL.md and four references that restate AGENTS.md; they already drift (exit codes of output_exists, key_unsupported, store_no_keyring; Bestandsnetze, Konnektor fault hints). Design: agents learn ti by running `ti agent` (AGENTS.md, matching the installed binary), `ti <cmd> --help` and `ti schema`; each text lives in one document (docs/README.md). The skill is only an entry point.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Safety rules and recipes AGENTS.md lacked are added to AGENTS.md, not to the skill
- [ ] #2 README wording is vendor-neutral; ti-cli Unreleased notes have an entry; just check is green
- [ ] #3 Samples for creating or editing a .kon are allowed; the skill never has an agent print a real .kon (it is a secret, TASK-136)
- [ ] #4 The skill lives in skills/ti (decision-9) as an entry point: with ti installed it runs ti agent, then --help and ti schema; without ti it reads the generated references/AGENTS.md and runs nothing; no hand-written command catalogue, exit-code table or error kinds
<!-- AC:END -->
