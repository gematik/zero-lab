---
id: TASK-233
title: 'spec/pki-validation: weak signature before chain_incomplete on a partial chain'
status: To Do
assignee: []
created_date: '2026-11-06T14:09:00Z'
labels:
  - spec
  - security
dependencies: []
priority: low
ordinal: 249000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-98.1 review: when the validator builds a partial chain of two or more certificates that does not reach an anchor, ti_pki::tls (and go/tipki, following it) reports signature_algorithm_not_allowed for a SHA-1/MD5/SHA-224 link before chain_incomplete, while the spec's check order puts the path (TLSV-020) first. Both refuse; only the code differs. Decide the order in the spec, add a corpus case, align Rust and Go.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the spec states the order and a corpus case pins it
- [ ] #2 ti-pki and go/tipki agree with it
<!-- AC:END -->
