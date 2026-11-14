---
id: TASK-287
title: >-
  ti pki verify: a certificate outside every TI environment gets a report, not
  an error
status: Done
assignee: []
created_date: '2026-11-11T18:35:00Z'
updated_date: '2026-11-14T16:54:00Z'
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
- [x] #1 verify without --env renders the report for such a certificate: INVALID, exit 1, error environment_undetected (no chain to a root of any TI environment; pass --env), no trust material loaded
- [x] #2 JSON: environment.name 'none', schema pki-verify.json updated, schema tests pass
- [x] #3 EnvironmentUndetected's message is one short line plus the hint; the detection steps appear with -v
- [x] #4 tests named after the behaviour; release notes (ti-client, ti-cli Unreleased)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Report built in ti-client (outside_ti): no session, no trust material; ValidationResult with the leaf alone so the CLI tree shows it, the issuer row says 'not under any TI root'. Schema: environment.name/detection.method gain 'none', trust oneOf null, finding code environment_undetected (verify_codes_are_ti_pkis now lists ti-pki's codes plus OUTSIDE_TI). CliError::detail feeds the -v lines in Output::error. With --connect, 0.6.1 already falls back to the web profile (server_profile).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti pki verify without --env reports a certificate outside every TI environment instead of failing: INVALID, exit 1, environment.name none, trust null, finding environment_undetected, the leaf shown with 'not under any TI root'. The undetected-environment error is one line; its detection steps appear with -v. Schema pki-verify.json and tests updated. Branch feat/ti-0.6.2, released in ti 0.6.2.
<!-- SECTION:FINAL_SUMMARY:END -->
