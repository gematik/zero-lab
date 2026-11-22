---
id: TASK-348
title: 'jwz: published to crates.io by trusted publishing from GitHub Actions'
status: To Do
assignee: []
created_date: '2026-11-16T19:40:00Z'
updated_date: '2026-11-22 15:22'
labels: []
dependencies: []
type: external
ordinal: 363000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz 0.1.0, 0.2.0 and 0.2.1 were published by the maintainer's account with an API token; crates.io records no trusted publishing for them. With crates.io trusted publishing (OIDC from a GitHub Actions workflow in gematik/zero-lab, no long-lived token), each release names the repository, run and commit it was built from, and consumers can trust jwz by its publisher in cargo vet, as zero-lab trusts the RustCrypto crates (supply-chain/audits.toml). Goes with TASK-239 (gematik GitHub team as owner). The publish stays the maintainer's decision: the workflow runs on a tag the maintainer pushes, or by hand.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 crates.io has a trusted publisher for jwz: the gematik/zero-lab repository and its release workflow
- [ ] #2 A workflow publishes jwz from a rust/jwz/v* tag without an API token, after the release gates (just audit for jwz)
- [ ] #3 The next jwz release shows trusted publishing data on crates.io; docs/development.md's release steps say how
<!-- AC:END -->
