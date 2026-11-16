---
id: TASK-344
title: 'epa/vau: fxamacker/cbor decodes strictly'
status: To Do
assignee: []
created_date: '2026-11-16T18:21:00Z'
labels: []
dependencies: []
ordinal: 359000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
decision-18: CBOR stays fxamacker, with strict options instead of the defaults. The spike's differential fuzz (doc-5) showed what the defaults accept: duplicate keys (last wins), case-folded field names, unknown and integer keys (a map of integer keys decodes as an empty M4), tags, null as nil, missing fields as zero values, trailing bytes after CertData and errors. Configure one DecMode: DupMapKeyEnforcedAPF, TagsForbidden, ExtraReturnErrors for unknown fields except where the spec says to ignore them (A_24425-01 VAU_Keys, A_26921 ASL_Keys), bounded MaxNestedLevels, MaxArrayElements, MaxMapPairs; refuse trailing bytes; bound every body read. The spike's fuzz seeds and lib-vau / libasl vectors (spike/asl-stdlib, go/epa/vau/testdata) come along as regression tests.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each input class above is refused with a reason, one TestServerRule28_ test each; the lib-vau and libasl vectors still decode
- [ ] #2 TestEPA_Connect passes against the reference environment with the strict mode
<!-- AC:END -->
