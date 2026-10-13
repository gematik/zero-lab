---
id: TASK-43
title: 'ti probe: group TI 1.0 and TI 2.0 endpoints'
status: To Do
assignee: []
created_date: '2026-10-13 18:10'
labels:
  - ti-cli
dependencies: []
references:
  - ti-cli/src/commands/probe.rs
  - ti-cli/src/probe/endpoints.json
priority: low
ordinal: 41000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti probe lists every endpoint of an environment in one flat list: IDP, Directory, eRX and the ePA Aktensysteme (TI 1.0 services) sit next to PoPP and the service-discovery catalog (TI 2.0, ZETA-protected) and the endpoints the catalog adds. Group the output by generation so it shows at a glance which part of the TI answers. The generation belongs in the endpoint data (ti-cli/src/probe/endpoints.json, TI_PROBE_ENDPOINTS_PATH, catalog-discovered endpoints), not inferred from the name.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each endpoint carries its TI generation (1.0 / 2.0); catalog-discovered endpoints are 2.0
- [ ] #2 text output shows a TI 1.0 and a TI 2.0 group, each with its own rows; live redraw still works
- [ ] #3 JSON report and ti-cli/schemas/probe.json carry the generation per endpoint
- [ ] #4 tests in ti-cli/tests/probe.rs and the unit tests cover the grouping
<!-- AC:END -->
