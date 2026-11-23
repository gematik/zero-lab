---
id: TASK-418
title: 'zaddy: OpenTelemetry 1.47.0 for GO-2026-6974 and GO-2026-6975'
status: In Progress
assignee: []
created_date: '2026-11-23T22:13:00Z'
labels:
  - go
  - zaddy
  - security
dependencies: []
priority: high
ordinal: 431000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
govulncheck (just check in go/) reports two advisories published for go.opentelemetry.io/otel v1.46.0, reachable in zaddy through Caddy: GO-2026-6975 (memory amplification in W3C baggage parsing, reached from zaddy.App.ServeHTTP) and GO-2026-6974 (AttributeValueLengthLimit bypass via U+FFFD in otel/sdk). Both are fixed in v1.47.0. The modules are indirect requirements of zaddy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zaddy requires the OpenTelemetry modules at the fixed versions, go mod tidy is clean, govulncheck reports nothing, and zaddy's tests pass
<!-- AC:END -->
