---
id: TASK-14
title: Align test structure of the ti-* crates with jwz
status: To Do
assignee: []
created_date: '2026-10-09 17:27'
labels:
  - tests
  - review
dependencies: []
priority: medium
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz's tests are built for human review: each test is named after the requirement it proves (rfc_7516_5_2_..., wycheproof_...), each tests/ file opens with a //! header listing what it covers, and every fixture directory has a PROVENANCE.md (source, version or commit, how to refresh). The other crates follow this unevenly (survey 2026-10-09): ti-pki has 241 tests named by behaviour while its 192 TUC_PKI/GS-A/RFC citations sit in src/, so a reviewer cannot go from a requirement to its test; ti-cli (87) and ti-connector-client (43) likewise, and their tests/fixtures have no provenance; ti-xmldsig is closest (tests named by spec rule tslsig_NNN); ti-report has no tests. Align crate by crate, ti-pki first.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-pki: every test that proves a TUC_PKI / GS-A / A_ / RFC rule is named after it, or the test file's //! header maps rules to tests
- [ ] #2 ti-cli, ti-connector-client, ti-wasm: same for the requirements they implement
- [ ] #3 Every tests/fixtures and tests/data directory has a PROVENANCE.md (source, version/commit, refresh steps)
- [ ] #4 ti-report has tests for its report output
- [ ] #5 No test changes behaviour: renames and headers only, apart from the new ti-report tests
<!-- AC:END -->
