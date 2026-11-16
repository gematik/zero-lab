---
id: TASK-346
title: 'epa/vau: byte order of the IV counter'
status: Done
assignee: []
created_date: '2026-11-16T18:21:00Z'
updated_date: '2026-11-16T20:51:00Z'
labels: []
dependencies: []
ordinal: 361000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the ASL spike (TASK-339): go/epa/vau writes the 64-bit counter in the record IV little-endian (channel.go ~248); gematik's libasl writes it big-endian (util.rs:303); gemSpec_Krypt says only 'IV = a ‖ Zähler' (A_24629, A_26927) and 'Network-Byte-Order' for the header counter. The server reads the IV from the record, so both interoperate. Ask gematik which is meant, then align.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The IV counter follows the reference implementations, recorded with their source, and a test pins it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-17 research: gematik lib-vau (Java, AbstractVauStateMachine.encryptVauMessage) builds IV = 4 random bytes || the request counter as ByteBuffer.putLong, i.e. big-endian, the same 8 bytes as the header counter. Andreas Hallof vau-protokoll (Python reference, minimal/encvau.py) uses a fully random 12-byte IV and a big-endian header counter; receivers take the IV from the record. libasl (ZETA) writes it big-endian. Only go/epa/vau wrote it little-endian. No question to gematik needed: align with lib-vau.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
gematik lib-vau writes the IV counter big-endian (ByteBuffer.putLong, the same bytes as the header counter); Hallof vau-protokoll uses a random IV, libasl big-endian. go/epa/vau now writes it big-endian; TestA_24628_TheIVCarriesTheCounterBigEndian pins it (fails on the old order). Full just check and live ePA connect (enforce) passed. No question to gematik needed. Unreleased; goes out with the next epa tag.
<!-- SECTION:FINAL_SUMMARY:END -->
