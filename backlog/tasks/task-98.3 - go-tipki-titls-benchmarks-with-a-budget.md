---
id: TASK-98.3
title: go/tipki/titls benchmarks with a budget
status: Done
assignee: []
created_date: '2026-11-06T14:01:00Z'
updated_date: '2026-11-06T18:25:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 246000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cold and cached verification per profile with TASK-97's budgets (5 ms cold, 10 µs cached), checked by a just recipe in go/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a just recipe fails when a budget is exceeded
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Benchmarks in go/tipki/titls (bench_test.go) for each profile, cold (fresh verifier each run) and cached (same chain and host again), on the corpus's valid chains with their OCSP answers stapled so no network takes part; a just recipe tls-bench in go/ runs them with -count and fails when a median exceeds 5 ms cold or 10 µs cached, as rust's tls-bench does.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/go-pki-validation (7ea0a898): go/tipki/titls/bench_test.go, BenchmarkTi/Web Cold/Cached on the corpus's valid chains with stapled OCSP; just tls-bench (go/) runs them on one core, -count 5, and fails when a median exceeds 5 ms cold or 10 µs cached. M1: ti 0.26 ms cold, 0.68 µs cached; web 0.20 ms cold, 0.84 µs cached. Failure path checked with a lowered budget.
<!-- SECTION:NOTES:END -->
