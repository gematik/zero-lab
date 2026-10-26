---
id: TASK-98
title: 'Go: TLS verification of TI endpoints through the shared rules'
status: To Do
assignee: []
created_date: '2026-10-15 05:20'
labels:
  - go
  - spec
  - keys
dependencies:
  - TASK-97
references:
  - docs/architecture.md
  - go/docs/design.md
priority: medium
ordinal: 96000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Go clients of TI endpoints (gemidp, epa, oidf) verify TLS peers with crypto/tls and the system roots. Under the trust contract (docs/architecture.md) they apply spec/pki-validation instead.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a tls.Config constructor whose VerifyConnection implements spec/pki-validation natively or through ti, used by every Go client of a TI endpoint, passing the shared corpus
<!-- AC:END -->
