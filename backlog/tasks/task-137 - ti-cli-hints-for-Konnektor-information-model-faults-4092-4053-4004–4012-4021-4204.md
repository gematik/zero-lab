---
id: TASK-137
title: >-
  ti-cli: hints for Konnektor information-model faults (4092, 4053, 4004–4012,
  4021, 4204)
status: Done
assignee: []
created_date: '2026-10-24 08:06'
updated_date: '2026-10-24 08:57'
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
- [x] #1 A Konnektor fault with one of the codes above carries a hint naming its cause and fix, the .kon fields concerned and, when known, the card's terminal
- [x] #2 The hints are in text output and in JSON (error kind and hint); the fault text and code stay unchanged
- [x] #3 Tests named after the gemSpec_Kon code (e.g. kon_4092_without_remote_pin_kt_hints_the_workplace) cover each hint with a recorded or synthetic fault
- [x] #4 The Unreleased notes of ti-cli list the hints
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
fault_hint in ti-cli/src/error.rs maps the gematik codes of the fault's trace (first known code wins) to a hint; 4263 (comfort signature) moved into the same table. The hint is static, so the card's terminal is named through `connector get cards` rather than its CtId: the fault does not carry the card. Tests: one unit test per code (kon_<code>_…), and kon_4092_verify_pin_without_remote_pin_kt_hints_the_workplace against the fake Konnektor checks code, text and hint in JSON and text. The JSON error document on stderr follows the PIN prompt line. HITL pending: the 4092 case at a real Konnektor.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Konnektor faults carry a hint by their gematik code (fault_hint in ti-cli/src/error.rs): 4004-4007, 4010-4012, 4021, 4053, 4060, 4092, 4093, 4204 and 4263, naming the .kon fields and where in the Konnektor's information model to fix it; code and text unchanged, hint in text and JSON. Unit test per code, end-to-end test of 4092 against the fake Konnektor; HITL at a real Konnektor passed (2026-10-24).
<!-- SECTION:FINAL_SUMMARY:END -->
