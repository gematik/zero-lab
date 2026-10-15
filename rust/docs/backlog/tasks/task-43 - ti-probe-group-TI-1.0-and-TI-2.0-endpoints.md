---
id: TASK-43
title: 'ti probe: group endpoints by access path (TI-VPN / Internet)'
status: To Do
assignee: []
created_date: '2026-10-13 18:10'
updated_date: '2026-10-15 12:16'
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
ti probe lists every endpoint of an environment in one flat list: the services reached through the TI VPN (IDP, Directory, eRX, the ePA Aktensysteme) sit next to the ones reached from the internet (PoPP, the service-discovery catalog and the endpoints it adds, ZETA-protected). Group the output by how an endpoint is reached, so it shows at a glance which part of the TI answers.

All of them are TI services; the groups name the access path, not a TI generation (TI 1.0 / TI 2.0 do not match reachability: idpd-internet is a TI 1.0 service reached from the internet):
- TI-VPN (ti-vpn in data): reached only through a Konnektor or TI-Gateway VPN
- Internet (internet in data): reached directly

The access path belongs in the endpoint data (ti-cli/src/probe/endpoints.json, TI_PROBE_ENDPOINTS_PATH, catalog-discovered endpoints), not inferred from the name.

Without the VPN none of the TI-VPN endpoints is reachable, and the probe should say so once rather than with a row of individual failures: the whole TI-VPN block is grayed out.

Endpoint names follow one convention, lowercase kebab-case:
- a service with several instances is <service>-<n>: epa-1, epa-2
- a singleton is the lowercase service name: catalog, fhir-directory, erx, popp
- the IDP is named after the network it serves: idpd-ti (group TI-VPN), idpd-internet (group Internet)
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each endpoint carries its access path (ti-vpn / internet); catalog-discovered endpoints are internet
- [ ] #2 text output shows a TI-VPN and an Internet group, each with its own rows; live redraw still works
- [ ] #3 JSON report and ti-cli/schemas/probe.json carry the access path per endpoint
- [ ] #4 tests in ti-cli/tests/probe.rs and the unit tests cover the grouping
- [ ] #5 endpoint names follow the convention: <service>-<n> for numbered instances (epa-1, epa-2), lowercase singletons (catalog, fhir-directory), idpd-ti / idpd-internet for the IDP
- [ ] #6 when the TI VPN is not available, the whole TI-VPN block is grayed out in the text output, and the JSON report says the block is unavailable
<!-- AC:END -->
