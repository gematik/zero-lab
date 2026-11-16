---
id: TASK-346
title: 'epa/vau: byte order of the IV counter'
status: To Do
assignee: []
created_date: '2026-11-16T18:21:00Z'
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
- [ ] #1 gematik's answer is recorded and the code follows it, with a test
<!-- AC:END -->
