---
id: TASK-225
title: 'ti-jwz: absorb jwz-brainpool as ti_jwz::brainpool'
status: To Do
assignee: []
created_date: '2026-11-06T06:43:00Z'
labels:
  - jwz
  - ti-jwz
dependencies: []
priority: medium
ordinal: 232000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Brainpool is TI-only (ADR 0001: not for new components), so it moves next to the TI profiles; jwz stays a JOSE library without it. Maintainer, 2026-11-06.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 jwz-brainpool's code, tests, interop data and generators live in ti-jwz behind the legacy feature; the crate is gone from the workspace
- [ ] #2 ti-idpd, ti-directory, ti-cli use ti_jwz::brainpool; jwz-backends, brainpool-absent, jwz-browser and the interop recipe cover the new place; just check passes
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. git mv sources, tests, data, interop, examples into ti-jwz (pure move commit). 2. module ti_jwz::brainpool behind legacy; deps bp256, ecdsa, elliptic-curve, signature move to ti-jwz (same versions, nothing new). 3. callers, Justfile recipes, mutation-scores.toml, unsafe-exceptions.md, workspace members, docs, ADR 0001, jwz doc comments, release notes. 4. just jwz-recheck for the browser stamp; just check.
<!-- SECTION:PLAN:END -->
