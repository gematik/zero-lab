---
id: TASK-231
title: >-
  service-discovery catalog presents an RSA-2048 certificate, refused under web
  (TLSV-041)
status: To Do
assignee: []
created_date: '2026-11-06T11:42:00Z'
labels:
  - ti-cli
  - security
  - external
dependencies: []
priority: medium
ordinal: 242000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-228's verifying probe on 2026-11-06: service-discovery.{prod,ref,test,dev}.ti-platform.de/catalog.json present a Google Trust Services (WR3) end-entity certificate with an RSA-2048 key. The web profile admits RSA end-entity keys of at least 3000 bits (TLSV-041, A_28976 / A_16176-01), so ti probe fails the catalog in every environment and cannot probe the instances it lists. Not a probe defect: the server falls short of gematik's rule. Report it to the operator through gematik, and decide whether the probe waits for the fix or the rule has an exception for this host (an exception would be recorded in spec/pki-validation, never by weakening the check).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the operator is told, with the rule and the observed certificate
- [ ] #2 a decision: wait for a compliant certificate, or a recorded exception
<!-- AC:END -->
