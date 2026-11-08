---
id: TASK-266
title: 'ti-client probe: product judgements to the product crates'
status: In Progress
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T09:27:00Z'
labels:
  - rust
dependencies: []
ordinal: 282000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti_client::probe judges the OIDC issuer, the directory redirect, ePA/eRP/ZETA answers and holds the endpoint catalog. They are reachability checks, but per decision-15 product knowledge belongs to the product crates. Decide per judgement where it belongs and move it. Found during TASK-250.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each judgement is in its product crate or noted why it is host connectivity
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer: where clients exist the probe goes into the crate, the others stay in ti-client for now. ti_idpd_client::probe and ti_directory_client::probe hold the path and the typed answer; ti-client asks and words it. ePA, eRP, ZETA and the service catalog stay in ti-client: no client crate yet.
<!-- SECTION:NOTES:END -->
