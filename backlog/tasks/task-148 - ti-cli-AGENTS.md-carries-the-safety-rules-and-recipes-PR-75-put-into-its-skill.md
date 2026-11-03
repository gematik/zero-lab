---
id: TASK-148
title: >-
  ti-cli: AGENTS.md carries the safety rules and recipes PR #75 put into its
  skill
status: Done
assignee: []
created_date: '2026-10-26T15:44:00Z'
updated_date: '2026-10-26T18:11:00Z'
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
- [x] #1 AGENTS.md holds the PR's safety rules and recipes that it lacked, worded per docs/conventions/agents.md
- [x] #2 AGENTS.md matches the binary: exit codes and error kinds, probe prod's Bestandsnetze, the Konnektor fault hints
- [x] #3 Never asks an agent to print a real .kon, .p12, PIN or token; placeholder .kon samples are allowed
- [x] #4 ti-cli Unreleased notes have an entry; just check is green
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti's AGENTS.md (printed by ti agent) gains: rules for agents per docs/conventions/agents.md (no real .kon, .p12, PINs, passwords, secrets or tokens asked for or printed; pasted secrets not repeated; secrets in output summarised; PIN, destructive and --force commands only on request; -k only when asked; how to report a verification); the exit-code table corrected and a complete Error kinds table (49 kinds; output_exists 2, key_unsupported 4, store_* 2 except busy/backend_error 5); the .kon format with a placeholder sample, its fields and the expansion rules; the Konnektor fault hints of TASK-137; PAdES output name; insecure_transport with -k; deactivating the comfort signature. A unit test (error::tests::the_guide_lists_every_error_kind_with_its_exit_code) builds one error per kind and fails when the table and the binary differ; checked by breaking the table once. The README points to AGENTS.md for exit codes instead of restating them. Release notes under ti-cli Unreleased. just check green. Stacked on feat/konnektor-fault-hints, which carries TASK-137/138.
<!-- SECTION:FINAL_SUMMARY:END -->
