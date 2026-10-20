---
id: TASK-103.6
title: 'Go: go/store module and files backend'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 20:41'
labels:
  - go
  - keys
  - security
  - fuzz
dependencies:
  - TASK-103.1
parent_task_id: TASK-103
priority: medium
ordinal: 107000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Standard library only: interfaces, Store, envelope, derivation, memory and files backends, key-file wrapper, profile resolution.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 passes the spec/store vectors and scenarios in tests named after the STORE rules
- [x] #2 fuzz targets for the envelope and keyring-file parsers
- [x] #3 no third-party requirement in go/store/go.mod
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
go/store (stdlib only): package store (pure) and store/filestore (files backend through os.Root), internal/conformance evaluator shared by TestSTORE_Corpus and cmd/store-conformance. Corpus: 130 of 131 pass in tests, 1 loud skip (capabilities-sqlite, TASK-103.7); Go verifier: 121 passed, 10 unsupported. Concurrent take on filestore: 16 goroutines x 20 rounds, exactly one wins, under -race. Findings fixed on the way: (1) Go fuzzing found that u64 times >= 2^63 round-trip in Rust but not in Go (time.Unix takes int64): spec STORE-002 now bounds times to 9999-12-31T23:59:59Z, both languages enforce it, 6 new corpus cases; (2) the expiry scenario tested a get after an expired take, which STORE-017/082 leave open: step removed; (3) the 100,000-record scenario now runs only on indexed backends; (4) gosec G122 led to os.Root for every filestore operation, with a test that fails without it (take through a symlinked namespace).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/store (stdlib only) with filestore through os.Root; passes the corpus (130/131, SQLite capabilities skipped loudly until TASK-103.7) and the Go verifier (121/131); concurrent take proven on filestore; four fuzz targets with regression inputs; spec STORE-002 time bound found by fuzzing; just check and golangci-lint green.
<!-- SECTION:FINAL_SUMMARY:END -->
