---
id: TASK-61
title: 'ti-connector-client: client TLS key as a function (rustls SigningKey)'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - ti-connector-client
  - keys
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 59000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The mutual TLS hands the PKCS#12 key to rustls by value (with_client_auth_cert); rustls supports keys as functions through sign::SigningKey and a client certificate resolver (private-key rule 1).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the transport takes a signing key behind rustls' SigningKey, so the client certificate key can live in an HSM; the PKCS#12 path builds one at the edge
<!-- AC:END -->
