---
id: TASK-103.7
title: 'Go: go/store/sqlite backend and zero-epa profiles'
status: In Progress
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-16 05:37'
labels:
  - go
  - epa
  - deps
dependencies:
  - TASK-103.6
parent_task_id: TASK-103
priority: medium
ordinal: 108000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SQLite backend as its own module so go/store stays dependency-free; driver ncruces/go-sqlite3 (no cgo) or modernc.org/sqlite after maintainer approval. zero-epa gains --profile and opens the shared store.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 driver approved with transitive cost recorded
- [x] #2 passes the operation scenarios
- [ ] #3 zero-epa --profile opens the profile's store
- [ ] #4 zero-epa implements the same section L commands with the same names and doctor JSON as ti
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Driver approved by the maintainer on 2026-10-16: github.com/ncruces/go-sqlite3 v0.35.6 (SQLite 3.53.4, no cgo), in its own module go/store/sqlite. Compiled: its packages, go-sqlite3-wasm/v6, julianday, golang.org/x/sys; 2.9 MB test binary. Alternatives weighed: modernc.org/sqlite v1.60.1 (about 30 modernc packages with libc emulation, 9.3 MB), mattn/go-sqlite3 (cgo).

go/sqlitestore (not go/store/sqlite): a nested module breaks just sync, which knows only go/<name> modules and go/<name>/vX tags. The corpus evaluator moved from go/store/internal/conformance to the exported go/store/storetest (Evaluate, RunCorpus, Load), as fstest/httptest do, so that a backend in another module runs the corpus.
Driver specifics: it creates -shm with the default mode, unlike SQLite's own VFS; Open creates -shm 0600 first and pins one connection so that it stays; the WAL follows modeof. It reports a file that is not a database only as text, so Open checks the 16-byte header. Errors are matched with errors.Is(err, sqlite3.BUSY) etc.
go.mod has no requirement on go/store yet: an unpublished version breaks even workspace builds. After pushing feat/store: go get github.com/gematik/zero-lab/go/store@<pseudo-version> in go/sqlitestore, then just tidy for go.sum (just sync only repins existing requirements).
Load check, same as TASK-103.4, Go 1.27 (wasm2go SQLite 3.53.4), no race detector: write 5.8 s; page through all 1.1 s; one tag value 2 ms; expiry range 33 ms; cleanup 4.7 s; under -race about 20x slower, so it skips with -short and race runs cover the concurrency tests.
Remaining: AC 3 and 4 (zero-epa --profile and the section L commands), after ti's in TASK-103.5 so that both follow one design.
<!-- SECTION:NOTES:END -->
