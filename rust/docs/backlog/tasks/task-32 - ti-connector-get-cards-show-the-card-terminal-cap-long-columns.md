---
id: TASK-32
title: 'ti connector get cards: show the card terminal, cap long columns'
status: To Do
assignee: []
created_date: '2026-10-11 11:31'
labels:
  - ti-cli
  - connector
dependencies: []
priority: low
ordinal: 30000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The JSON report of get cards already carries terminal (CtId) and slot, but the text and Markdown table does not show which terminal a card sits in. Add a TERMINAL column (CtId, with the slot) to card_table, used by get cards and describe card. Long identifiers, especially UUID-shaped card handles and CtIds, should not widen the table: cap such columns (e.g. first and last characters with an ellipsis in the middle, full value in JSON and with -v), so the table fits a normal terminal width.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 get cards and describe card show the terminal (CtId and slot) per card in text and Markdown
- [ ] #2 UUID-shaped or otherwise long values in the table are shortened to a fixed width with an ellipsis; JSON keeps the full values
<!-- AC:END -->
