---
id: TASK-118
title: 'ti/connector: show the PIN unlock status in connector describe card'
status: To Do
assignee: []
created_date: '2026-10-20 11:32'
labels:
  - ti-cli
  - connector
dependencies: []
priority: medium
ordinal: 103000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
connector describe card should say whether the card's PIN is unlocked (freigeschaltet), so that a user sees before signing or authenticating whether PIN entry is needed. The Konnektor's CardService GetPinStatus answers it (PinStatus: VERIFIED, TRANSPORT_PIN, EMPTY_PIN, BLOCKED, VERIFIABLE, DISABLED, with the remaining retries); the generated bindings have it (ti-connector-client/src/api/gematik/conn/cardservice812.rs) but the client API and ti do not use it yet. For SMC-B PIN.SMC, for HBA PIN.CH and PIN.QES.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-connector-client offers the PIN status of a card and PIN type through its typed API
- [ ] #2 connector describe card shows each PIN's status and remaining retries, in text and JSON (schema updated)
- [ ] #3 a test against the fake Konnektor covers verified, verifiable and blocked
<!-- AC:END -->
