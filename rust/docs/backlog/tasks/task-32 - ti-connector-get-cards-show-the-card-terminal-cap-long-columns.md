---
id: TASK-32
title: 'ti connector get cards: show the card terminal, cap long columns'
status: Done
assignee: []
created_date: '2026-10-11 11:31'
updated_date: '2026-10-20 19:15'
labels:
  - ti-cli
  - connector
dependencies: []
priority: low
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The JSON report of get cards already carries terminal (CtId) and slot, but the text and Markdown table does not show which terminal a card sits in. Add a TERMINAL column (CtId, with the slot) to card_table, used by get cards and describe card. Long identifiers, especially UUID-shaped card handles and CtIds, should not widen the table: cap such columns (e.g. first and last characters with an ellipsis in the middle, full value in JSON and with -v), so the table fits a normal terminal width.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 get cards and describe card show the terminal (CtId and slot) per card in text and Markdown
- [x] #2 UUID-shaped or otherwise long values in the table are shortened to a fixed width with an ellipsis; JSON keeps the full values
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
HITL open: get cards against a real Konnektor (maintainer).

HITL passed (maintainer, 2026-10-20): get cards and get certificates against a real Konnektor; get certificates names a shared subject and Telematik-ID once above the table.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
get cards and get certificates have a TERMINAL column (CtId · slot N). Handles and terminal IDs longer than 20 characters are shortened to start…end in the tables of get cards, get certificates, get identities and get expiration; -v and JSON keep them whole. Tests: card_table_shows_the_terminal_and_shortens_long_handles (fake Konnektor with a UUID-shaped handle), long_identifiers_are_shortened_unless_full.
<!-- SECTION:FINAL_SUMMARY:END -->
