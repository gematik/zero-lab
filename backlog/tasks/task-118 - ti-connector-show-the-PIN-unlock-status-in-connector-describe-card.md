---
id: TASK-118
title: 'ti/connector: show the PIN unlock status in connector describe card'
status: Done
assignee: []
created_date: '2026-10-20 11:32'
updated_date: '2026-10-20 19:15'
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
- [x] #1 ti-connector-client offers the PIN status of a card and PIN type through its typed API
- [x] #2 connector describe card shows each PIN's status and remaining retries, in text and JSON (schema updated)
- [x] #3 a test against the fake Konnektor covers verified, verifiable and blocked
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
HITL open: describe card against a real Konnektor (maintainer).

HITL passed (maintainer, 2026-10-20): describe card against a real Konnektor (SMC-B, PIN.SMC verified); describe card also shows the Telematik-ID from C.AUT, local insert time and valid until (the Konnektor's CertificateExpirationDate, date only).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-connector-client already had Pins::status (GetPinStatus) with PinType::for_card. describe card reads each user PIN of the card type: JSON pins[] {pin, status, left_tries, error} (schema updated), text one field per PIN: verified, PIN entry needed · N tries left, transport PIN, no PIN set, blocked: unblock with the PUK, disabled. A failed query is reported per PIN. Test describe_card_shows_each_pin_status against the fake Konnektor: verified (SMC-B), verifiable and blocked (HBA), none (SMC-KT).
<!-- SECTION:FINAL_SUMMARY:END -->
