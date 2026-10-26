---
id: TASK-137
title: >-
  ti-cli: hints for Konnektor information-model faults (4092, 4053, 4004–4012,
  4021, 4204)
status: To Do
assignee: []
created_date: '2026-10-24 08:06'
labels:
  - ti-cli
  - connector
  - ux
dependencies: []
priority: medium
ordinal: 148000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti passes Konnektor SOAP faults on without explanation, e.g. `SOAP fault SOAP-ENV:Server: Remote-PIN-KT benötigt aber für diesen Arbeitsplatz nicht definiert (4092 …)`. The error codes about the information model (Mandant, client system, workplace, card terminal) mean a configuration error in the Konnektor or in the .kon file, which the user can fix if told where to look.

From gemSpec_Kon V5.28.0 (TUC_KON_012/019/021, the access authorization service's error table):
- **4092:** no Remote-PIN-KT is configured for the workplace, and the card is in a card terminal not assigned locally to the workplace.
  - Fix: assign the terminal locally, or set a Remote-PIN-KT for the workplace in the Konnektor, or use a workplaceId to which the card's terminal is assigned locally.
- **4053:** remote PIN entry is not possible: an eGK in a terminal not assigned locally to the workplace.
- **4004, 4005, 4006, 4007:** unknown Mandant, client system, workplace or card terminal ID.
- **4010, 4011, 4012:** client system, workplace or card terminal not assigned to the Mandant.
- **4021:** mandantId, clientSystemId or workplaceId missing. The Konnektor may report 4021 instead of 4004 to 4006 at the external interface, so the hint names all three IDs.
- **4204:** the client system from the call context could not be authenticated (credentials, ANCL_CAUT_MODE).
- **4093, 4060:** the card or the terminal is busy in another session.

The hint names the .kon fields concerned and the card's terminal (CtId, slot) when it is known.

Related: TASK-136 (`config test` reuses the hints).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A Konnektor fault with one of the codes above carries a hint naming its cause and fix, the .kon fields concerned and, when known, the card's terminal
- [ ] #2 The hints are in text output and in JSON (error kind and hint); the fault text and code stay unchanged
- [ ] #3 Tests named after the gemSpec_Kon code (e.g. kon_4092_without_remote_pin_kt_hints_the_workplace) cover each hint with a recorded or synthetic fault
- [ ] #4 The Unreleased notes of ti-cli list the hints
<!-- AC:END -->
