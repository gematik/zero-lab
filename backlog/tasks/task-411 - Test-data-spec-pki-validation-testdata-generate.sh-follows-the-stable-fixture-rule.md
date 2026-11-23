---
id: TASK-411
title: >-
  Test data: spec/pki-validation/testdata/generate.sh follows the stable fixture
  rule
status: To Do
assignee: []
created_date: '2026-11-23T20:29:00Z'
labels:
  - testing
dependencies: []
priority: low
ordinal: 424000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
spec/pki-validation/testdata/generate.sh rebuilds all of its outputs on every run (69 committed files, keys in a temporary directory, counted serials; shared by Rust and Go), so adding one fixture rewrites the others. docs/design/testing.md 'Generated fixtures are stable' (TASK-410) asks for committed TEST-ONLY inputs, name-derived serials, deterministic signatures and a generator that writes only what is missing, rebuilding everything only with FORCE=1. rust/ti-pki/tests/pki/lib.sh is the worked example.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A second run of the generator changes no file, a FORCE=1 rebuild reproduces the same bytes except the outputs the generator names as randomised, and the tests that read the fixtures pass on the switch commit
<!-- AC:END -->
