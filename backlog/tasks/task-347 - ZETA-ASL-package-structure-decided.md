---
id: TASK-347
title: 'ZETA/ASL: package structure decided'
status: To Do
assignee: []
created_date: '2026-11-16T18:21:00Z'
labels: []
dependencies: []
ordinal: 362000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
decision-18: ASL is built in zero-lab, later. Before that, decide where it lives: (a) a profile beside VAU in go/epa/vau, as the spike did; (b) a protocol package both VAU and ASL use (handshake, channel, messages per profile), with go/epa and a ZETA client/server as consumers; (c) an own module go/asl. Inputs: the spike branch spike/asl-stdlib and doc-5, consumers (zeta-pdp-go as server/PEP, a ZETA client), the dependency rules (decision-13: format deps in hosts).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A backlog decision names the structure and the consumers, and the ASL implementation task is created from it
<!-- AC:END -->
