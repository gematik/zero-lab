---
id: TASK-13
title: 'ureq: custom TLS verifier without the unversioned API'
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - ti-connector-client
  - deps
  - watch
dependencies: []
priority: low
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti_connector_client::ureq uses ureq's unversioned transport API (ureq pinned ~3.4) because TlsConfig takes no certificate verifier and a Konnektor needs Go's semantics (.kon pins, expectedHost as SNI). Move off it when ureq accepts a custom verifier or rustls config, or move the adapter to its own crate before ti-connector-client 1.0 (Known compromises).
<!-- SECTION:DESCRIPTION:END -->
