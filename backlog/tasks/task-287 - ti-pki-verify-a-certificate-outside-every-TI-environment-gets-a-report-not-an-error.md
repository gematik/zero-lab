---
id: TASK-287
title: >-
  ti pki verify: a certificate outside every TI environment gets a report, not
  an error
status: To Do
assignee: []
created_date: '2026-11-11T18:35:00Z'
labels:
  - ti-cli
dependencies: []
ordinal: 303000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti pki verify <file> with a certificate that shows no TI environment (no embedded root, no chain to one, no TEST-ONLY/NOT-VALID marker or TI revocation host) fails with exit 2 and a long nested message listing each detection step. Maintainer (2026-11-11): show the certificate and that it is invalid against TI trust; shorten the error where it remains (idp-trust), steps only with -v.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 verify without --env renders the report for such a certificate: INVALID, exit 1, error environment_undetected (no chain to a root of any TI environment; pass --env), no trust material loaded
- [ ] #2 JSON: environment.name 'none', schema pki-verify.json updated, schema tests pass
- [ ] #3 EnvironmentUndetected's message is one short line plus the hint; the detection steps appear with -v
- [ ] #4 tests named after the behaviour; release notes (ti-client, ti-cli Unreleased)
<!-- AC:END -->
