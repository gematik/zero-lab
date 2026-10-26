---
id: TASK-138
title: >-
  ti probe prod: the SNK (KV-SafeNet) through the Konnektor's Bestandsnetz
  routing, a warning when unreachable
status: Done
assignee: []
created_date: 2026-10-24 08:23
updated_date: '2026-10-26T14:54:00Z'
labels:
  - ti-cli
  - probe
milestone: m-0
dependencies: []
priority: medium
ordinal: 149000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
probe prod checks the Sicheres Netz der KVen: gematik's Bestandsnetze.xml (http://download.crl.ti-dienste.de/bestandsnetze/Bestandsnetze.xml, v2.1.36) lists SNK as KV-SafeNet, 188.144.0.0/15, domain kv-safenet.de. portal.kv-safenet.de (188.144.7.178) answers 200 only through a TI VPN with Bestandsnetz routing. A practice need not have SNK booked, so an unreachable SNK is a warning, not a failure; it gets its own access path, bestandsnetz, so that it does not decide whether the TI-VPN block is available.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 probe prod has an snk probe of https://portal.kv-safenet.de in an access path bestandsnetz (Bestandsnetze)
- [x] #2 Failures in the bestandsnetz path are warnings with the cause; the exit code stays 0 for them; the block says once when it is not reachable
- [x] #3 The JSON schema, AGENTS.md, development.md and the Unreleased notes describe the path; tests prove the warning and the exit code
- [x] #4 HITL: probe prod with the TI VPN shows snk ok
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Planned with the maintainer: a section Bestandsnetze (access bestandsnetz) with all 17 networks of Bestandsnetze.xml 2.1.36, warnings only. A network with a known HTTPS host is probed there (snk: portal.kv-safenet.de, orgti: ekh.organspende-register.de), the others with kind dns, a TCP connection to the first DNS server of the network. Those that do not answer share one line (! not routed: …); rows only for the ones that answered. Outcome.answered (and answered in JSON) decides access_paths.available, since a Bestandsnetz failure is a warning. Measured 2026-10-24 through the maintainer's TI VPN: only SNK routed; snk http 200, the others timeout; exit 0.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
probe prod has a Bestandsnetze section (access bestandsnetz) with the 17 networks of gematik's Bestandsnetze.xml 2.1.36: a known HTTPS host where there is one (snk, orgti), else a TCP connection to the first DNS server (kind dns). Every failure there is a warning, the exit code stays 0, and those not routed share one line; JSON probes carry answered, which decides access_paths.available. Unit and integration tests; HITL through the TI VPN passed (2026-10-24).
<!-- SECTION:FINAL_SUMMARY:END -->
