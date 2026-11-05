---
id: TASK-83
title: 'Go tests: name the requirement they prove'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T21:29:00Z'
labels:
  - go
  - tests
dependencies: []
references:
  - docs/design/testing.md
priority: medium
ordinal: 81000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
15 of 75 Go test files cite any requirement and none follows the naming convention (docs/design/testing.md, Tests name the requirement they prove).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 tests of security rules in pdp, pep, oauth, oidf, dpop, nonce and epa named after their requirement
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On worktree-agent-a326a8befd23c5f03 (a02a16b0..d17120fb, one commit per module): 148 tests renamed in nonce, epa, pdp, pep, pep/proxy, openid (was oauth), oidf; dpop already traced (TestTraceability). New prefixes: TestServerRuleN_, TestKeysRuleN_, TestA_nnnnn_, TestOIDCCore_, TestOIDCDiscovery_, TestOIDF_. Own-policy tests and loose fits kept their names. Merges with TASK-89 with one conflict (oidf api_key_test: the api_key_path test is gone). Findings: TASK-215, TASK-216, TASK-217.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
148 security tests in nonce, epa, pdp, pep, pep/proxy, openid and oidf are named after the requirement they prove (TestServerRuleN_, TestKeysRuleN_, TestA_nnnnn_, TestRFCnnnn_, TestOIDC…_, TestOIDF_). The oidf env test keeps its name, as the development key is now an environment variable by exception. Findings: TASK-215, TASK-216, TASK-217. Merged into main as 365dd5cd..f3d9d93f.
<!-- SECTION:FINAL_SUMMARY:END -->
