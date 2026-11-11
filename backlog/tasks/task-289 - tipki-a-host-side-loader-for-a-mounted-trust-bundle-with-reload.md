---
id: TASK-289
title: 'tipki: a host-side loader for a mounted trust bundle, with reload'
status: To Do
assignee: []
created_date: '2026-11-11T19:44:00Z'
labels:
  - tipki
  - go
dependencies: []
references:
  - docs/design/servers.md
  - go/idpd/trust.go
priority: medium
ordinal: 305000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Server rule: trust material comes from a mounted directory a producer job writes (docs/design/servers.md, go/docs/design.md section 10). The code that does this, reading the bundle file, LoadTrustStore under the environment's anchors, settling the signer's status, rereading on change, keeping the store in use when a replacement does not verify and failing closed at MaxBundleAge, exists only inside idpd (idpd/trust.go, BundleTrust) bound to the IDP certificates. tipki/fetch covers the download case only. zeta-pdp-go had to write the same again (internal/host/trust.go, about 110 lines, with gunzip so a bundle fits a ConfigMap), and every further server will. A bundle is 808 kB plain and 190 kB gzipped, against the 1 MiB a ConfigMap or Secret holds.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A package beside tipki/fetch hands out the current TrustStore of a mounted bundle file and rereads it, with the same fail-closed rules
- [ ] #2 It accepts a gzipped bundle, or ti pki trust export writes one that fits a ConfigMap, and the choice is documented
- [ ] #3 idpd uses it instead of its own loader
<!-- AC:END -->
