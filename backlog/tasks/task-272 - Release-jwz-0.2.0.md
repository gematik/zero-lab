---
id: TASK-272
title: Release jwz 0.2.0
status: In Progress
assignee: []
created_date: '2026-11-08T12:06:00Z'
updated_date: '2026-11-08T15:54:00Z'
labels:
  - jwz
  - release
milestone: m-1
dependencies:
  - TASK-276
  - TASK-278
priority: medium
ordinal: 288000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz 0.2.0 carries TASK-243 (KeyResolver, verify_with), TASK-271 (profiles bind signing and keys; a breaking change), TASK-241 (RFC 9864) and TASK-258 (RFC 8725 traced), with TASK-251 (ti-client's RemoteJwks) as the API's first user before publishing. jwz's browser stamp hashes the workspace Cargo.toml, so every manifest change comes first and the stamps are rechecked once. The branch chore/ureq-3.5 is stale (its files moved into ti-client in TASK-249): the ureq bump is redone in ti-client and the branch deleted.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 every manifest change is in before the stamps: the ureq bump in ti-client, ti-jwks removed (TASK-251)
- [ ] #2 one jwz-recheck, the mutation score recorded, the traceability table blessed, just semver confirms the minor bump
- [ ] #3 release notes under Unreleased for jwz (and ti-jwz where it changes), then just release jwz=0.2.0; published to crates.io by the maintainer
<!-- AC:END -->
