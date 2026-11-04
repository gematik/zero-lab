---
id: TASK-212
title: 'ti-cli: one user ID for every call on an HBA'
status: In Progress
assignee: []
created_date: '2026-11-04T17:05:00Z'
updated_date: '2026-11-04T19:01:00Z'
labels:
  - ti-cli
  - ti-connector-client
dependencies: []
priority: medium
ordinal: 219000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Konnektor keys an HBA card session by card, client system and user ID, and every such session has one (gemSpec_Kon constraints C2, C16). ti sends the comfort ID on comfort calls and on sign, but on PIN commands, verify certificate and export it sends the userId of the .kon or none. So while comfort signature is on, those calls get 4018 (TAB_KON_514-01) until it is deactivated, and PIN commands on an HBA need a userId in the .kon although the user has no reason to choose one. Found in the hardware test of TASK-208.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 While comfort signature is on for an HBA, every ti call on that HBA uses its comfort ID and no longer gets 4018 for it
- [x] #2 Without a comfort ID, a call on an HBA uses the userId of the .kon when set
- [x] #3 Without either, a call on an HBA uses a generated ID kept per HBA in the profile's state, so PIN commands work without setup
- [x] #4 comfort activate still uses a new random ID each time (A_21528, A_20074)
- [x] #5 Calls on other cards send what they sent before
- [x] #6 A 4018 hint says what it means and what to do
- [x] #7 AGENTS.md and the README explain which ID is used; the ID stays masked in -vv
- [x] #8 Proven by the maintainer against a real Konnektor and HBA
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Rule, per call on a card of the HBA family (HBA, HBA-qSig, ZOD 2.0, HBAx): --comfort-user-id, else the stored comfort ID, else the userId of the .kon, else a generated ID kept in hba-user/<Konnektor>/<card> of the profile's state, with the same private-file checks as the comfort ID.

1. ti-connector-client: Pins, Certificates, Auth and Encryption get as_user(Option<&ComfortUserId>) as Signatures has; calls without it send the .kon's context. Signatures::as_user takes an Option too.
2. ti-cli: card_user(session, card) applies the rule; every call naming an HBA goes through it, including sign, describe, identity.
3. comfort activate keeps its own new ID; comfort deactivate has no context and keeps it so.
4. fault_hint for 4018. AGENTS.md, README, release notes.
5. The fake Konnektor enforces 4018, so tests fail on a wrong ID as the real one does.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Spec: GetSignatureMode and ActivateComfortSignature run TUC_KON_000, DeactivateComfortSignature has no context, so comfort deactivate works from any profile. comfort status from another profile than the one that activated gets 4018 by the spec. AC 8 waits for an HBA and Konnektor that accept each other: HBA-108's C.QES is INVALID on the secunet Konnektor (1027, 1059), which blocks signing but not PIN and certificate calls.
<!-- SECTION:NOTES:END -->
