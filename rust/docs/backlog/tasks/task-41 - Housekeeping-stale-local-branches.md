---
id: TASK-41
title: 'Housekeeping: stale local branches'
status: Done
assignee: []
created_date: '2026-10-11 11:48'
updated_date: '2026-10-20 18:53'
labels:
  - chore
dependencies: []
priority: low
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
21 local branches, 9 merged into main (bugfix/ti-types-wasm-clock, chore/archive-gempki, chore/rust-backlog, feat/directory-owner-auth, feat/idpd-tsl-verify, feat/ocsp-cache, feat/pki-inspect-short, feat/pki-rca7-nist, rust/jwz-m1) and safe to delete. Unmerged from June 2026, with patches main lacks per git cherry: chore/go-tooling (modernize), chore/valkey-to-redis, epa-env-tests, refactor/brainpool-josebp, refactor/product-client-registry; without such patches (superseded): chore/rm-pdp-scratch, feat/brainpool-jwxbp, refactor/inject-http-client, test/gemidp-smcb. feat/connector-card-sessions (2026-10-10) is TASK-9's work in progress: keep.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 merged branches deleted; each unmerged June branch either merged, turned into a task, or deleted with the user's ok
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
2026-10-20: 15 local branches merged into main deleted; the four superseded June branches (chore/rm-pdp-scratch, feat/brainpool-jwxbp, refactor/inject-http-client, test/gemidp-smcb) and, after a check that main holds their content, the five with unmerged patches (chore/go-tooling, chore/valkey-to-redis, epa-env-tests, refactor/brainpool-josebp, refactor/product-client-registry) deleted with the maintainer's ok. Left: main, feat/connector-card-sessions (TASK-9), spike/go-rust-bridge (TASK-116).
<!-- SECTION:FINAL_SUMMARY:END -->
