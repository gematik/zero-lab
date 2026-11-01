---
id: TASK-173
title: >-
  ti-pki, ti: trust-material producer for containers (export of .xml, .sig,
  .ocsp and roots.json with a manifest; CronJob to a ConfigMap or volume;
  air-gapped import)
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - rust
  - ti-pki
  - ti-cli
  - interop
dependencies:
  - TASK-166
priority: medium
ordinal: 183000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
In Docker and Kubernetes, fetching and renewing trust material is separate from the consumers (maintainer, 2026-11-01). The consumer side exists in ti-pki: the file transport written for a mounted ConfigMap (load/file.rs, follows the ..data symlink swap), StaticLoader and Bundle keyed by anchor hash, and the Reloader with its policy (hourly with jitter, stale after 6 h of failures, hard expiry 24 h in production, reload before NextUpdate). Missing is the producer: a command that fetches .xml, .sig, .ocsp and roots.json as a consistent set, verifies it, and writes it with a manifest (fetch time, anchor hash, environment) to a directory; run as a Kubernetes CronJob from the product image, hourly (the .ocsp renews hourly; hash compare before download per A_30044), writing a ConfigMap (the set is about 600 KB today, under the 1 MiB limit; a volume is the fallback) or a volume. Air-gapped: the same export on a connected machine, imported by the operator; consumers verify on load and age it out by the hard expiry, so a stale import fails closed (docs/architecture.md offline operation requires a daily import). Compose and VM deployments use the same export into a shared directory. Consumers keep nothing on disk. Rules: docs/architecture.md offline and air-gapped operation, trust from verification only; docs/design/servers.md 8, 12.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti pki trust export writes the set with a manifest; a consumer loading the directory through the file transport verifies it and reports its age and source
- [ ] #2 a CronJob manifest and a compose example from the product image, documented in the deployment guide; the ConfigMap size limit stated with the volume fallback
- [ ] #3 an import older than the hard expiry is refused; tested with the reloader
<!-- AC:END -->
