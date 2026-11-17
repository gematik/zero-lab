---
id: TASK-289
title: 'tipki: a host-side loader for a mounted trust bundle, with reload'
status: Done
assignee: []
created_date: '2026-11-11T19:44:00Z'
updated_date: '2026-11-17T08:11:00Z'
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
- [x] #1 A package beside tipki/fetch hands out the current TrustStore of a mounted bundle file and rereads it, with the same fail-closed rules
- [x] #2 It accepts a gzipped bundle, or ti pki trust export writes one that fits a ConfigMap, and the choice is documented
- [x] #3 idpd uses it instead of its own loader
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Built on fix/tipki-bundle-loader (fcf499b4, 6d644a93), merged into fix/elder-tasks. go/tipki/bundlefile: New/Current/Source/Reload/Close; change detected by SHA-256 of the content (ConfigMap symlink swap); a replacement that does not verify, is older or carries an older list never replaces the store in use, which stands until fetched_at + 24 h or NextUpdate. Gzip accepted in the loader (one member, 16 MiB read and decompressed), ti pki trust export unchanged. idpd BundleTrust uses it; IDPV-005 reworded: a bad replacement keeps the bundle in use until its age limit (maintainer agreed 2026-11-17). Breaking for idpd: NewBundleTrust takes a *slog.Logger, ClientConfig.Logger, BundleTrust.Close.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/tipki/bundlefile hands out the current TrustStore of a mounted bundle (plain or gzipped, 16 MiB bounds), reread on content change, never replaced by one that does not verify or is older; idpd BundleTrust uses it; IDPV-005 as agreed. Released with tipki v0.33.0 and idpd v0.3.0.
<!-- SECTION:FINAL_SUMMARY:END -->
