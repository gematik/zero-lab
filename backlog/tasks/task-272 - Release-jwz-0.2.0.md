---
id: TASK-272
title: Release jwz 0.2.0
status: Done
assignee: []
created_date: '2026-11-08T12:06:00Z'
updated_date: '2026-11-08T18:25:00Z'
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
- [x] #2 one jwz-recheck, the mutation score recorded, the traceability table blessed, just semver confirms the minor bump
- [x] #3 release notes under Unreleased for jwz (and ti-jwz where it changes), then just release jwz=0.2.0; published to crates.io by the maintainer
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
jwz-recheck: Kani 7/7 (compact_split_is_exact now ~530 s, the Arc cause on its error paths), hax/F*, browser 6+3. Mutation 0.9519 (653/686), gate passes; survivors outside the release in TASK-279. just semver: the recipe built jwz with all features, so the rsa compile_error stopped it; it now checks jwz with JWZ_FEATURES. Its findings at 0.1.0 are the intended breaking changes plus Error losing UnwindSafe/RefUnwindSafe (the Arc<dyn Error> cause), now in the release notes; just release re-runs it after the bump.

Released 2026-11-08: just release jwz=0.2.0 (36 min: check-full incl. cross clippy, mutation gate, advisories, vet, msrv, semver 'no update required' at 0.2.0, jwz-recheck), commit fc9f2284 and tag rust/jwz/v0.2.0 pushed. Open: cargo publish by the maintainer (AC 3), then TASK-239.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
jwz 0.2.0 released 2026-11-08: manifests first (ureq 3.5 in ti-client, ti-jwks removed), one restamp (Kani 7/7, hax/F*, browser), mutation 0.9519, semver checked with jwz's features (recipe fixed), full check, merge, just release (36 min), tag rust/jwz/v0.2.0 pushed, published to crates.io by the maintainer. Its README still described 0.1; fixed for 0.2.1.
<!-- SECTION:FINAL_SUMMARY:END -->
