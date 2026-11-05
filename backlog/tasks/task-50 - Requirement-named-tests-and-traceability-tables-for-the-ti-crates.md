---
id: TASK-50
title: Requirement-named tests and traceability tables for the ti crates
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-05T22:12:00Z'
labels:
  - tests
  - spec
dependencies:
  - TASK-14
references:
  - docs/design/testing.md
priority: medium
ordinal: 48000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/design/testing.md, Tests name the requirement they prove: tests carry the requirement ID in their name and code cites it. Only jwz has a traceability table today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 tests of security rules in ti-pki, ti-xmldsig, ti-pkcs12, ti-idpd, ti-directory and ti-connector-client named after their requirement, and a generated, checked traceability table per crate like jwz's
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On worktree-agent-a12070c6fad0cf3a1 (40660e8f..cd9395d4, 10 commits), together with TASK-14. New dev-only crate rust/traceability (std, publish=false); tables in ti-pki, ti-pkcs12, ti-idpd, ti-directory, ti-connector-client, ti-cli, ti-wasm; TRACE_BLESS=1 cargo test -p <crate> --test traceability. 129 tests renamed (ti-pki 90). Citations checked against gemSpec_PKI 2.28, TSL 1.25, Krypt 2.50, IDP_Frontend 1.7.1, IDP_Dienst 2.2.0, Kon 5.28.0. Gaps listed in each crate's docs/traceability.md. Findings: TASK-222 (path_corpus gating), TASK-223 (ti-idpd IDPV divergence).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Requirement-named tests and generated, checked traceability tables (rust/traceability, TRACE_BLESS=1) for ti-pki, ti-pkcs12, ti-idpd, ti-directory, ti-connector-client, ti-cli and ti-wasm; 129 tests renamed. Merged into main at 50ea3d15.
<!-- SECTION:FINAL_SUMMARY:END -->
