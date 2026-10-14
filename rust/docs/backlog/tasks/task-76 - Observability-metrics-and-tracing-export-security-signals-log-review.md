---
id: TASK-76
title: 'Observability: metrics and tracing export, security signals, log review'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - server
  - observability
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 74000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No OpenTelemetry or Prometheus export, no security-signal metrics or alerts, logs not reviewed for personal data or tokens (server rule 14).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 one instrumentation interface with OTel and Prometheus exporters chosen in cmd/, the security signals of rule 14 as metrics, and slog output reviewed
<!-- AC:END -->
