---
id: TASK-103.4
title: 'ti-cli: files and SQLite store backends'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-16 05:54'
labels:
  - ti-cli
  - deps
dependencies:
  - TASK-103.3
parent_task_id: TASK-103
priority: medium
ordinal: 105000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
I/O backends as private ti-cli modules: files (sharded sealed files, STORE-6xx) and SQLite (STORE-5xx) via rusqlite with bundled, after maintainer approval of the dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 rusqlite approved with transitive cost recorded
- [x] #2 both backends pass the operation scenarios
- [x] #3 100k-record load check within the recorded time budget
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Dependency approved by the maintainer on 2026-10-16: rusqlite 0.40.2 with bundled (SQLite 3.53.2), in ti-cli only. Runtime crates: libsqlite3-sys, hashlink/hashbrown/foldhash, bitflags, smallvec, fallible-iterator, fallible-streaming-iterator; build: cc (find-msvc-tools, shlex), pkg-config, vcpkg. Alternatives weighed: system SQLite (version varies, none on Windows), sqlx (async, larger tree), turso/limbo (young file compatibility).

Backends in ti-cli/src/store: sqlite.rs (rusqlite), files.rs, mod.rs (Kind from TI_STORE_BACKEND, AnyBackend). Unused outside tests until TASK-103.5, which removes the module's expect(dead_code).
Found on the way: spec/store gave the application id as 1515934548, but 0x5A4C5354 ("ZLST") is 1514951508; STORE-070 and schema.sql corrected before any database existed.
Tag queries drive from the tags table and order by its name (EXPLAIN: PRIMARY KEY (ns, field, tag, name>?)); ordering by records.name made SQLite walk the namespace (54 ms, now 0.7 ms). Expiry-range queries without tags still walk it: TASK-113.
Creating one database from several processes at once can return busy before the busy handler runs (the WAL switch); creation retries until the 5 s busy timeout.
The files backend has no os.Root in Rust's std: each directory below the root is checked with symlink_metadata, files are created with create_new, and a claimed file is checked before it is read; a test proves a linked namespace and a linked record file are refused (and fails without the checks).
Load check (TASK-103.4 AC 3), 100,000 records of 400 bytes with one tag each, state.db (synchronous FULL, secure_delete), Apple M-series, release / debug: write in 100 batches of 1000 3.2 s / 4.8 s; page through all 110 ms / 520 ms; one tag value (100 records) 0.7 ms / 1.3 ms; expiry range (500) 16 ms / 31 ms; cleanup of all in batches of 1000 3.5 s / 4.9 s. Budget in the test: 60 s total, 50 ms for the tag query (debug).

rusqlite without its default cache feature: its hashlink brings foldhash (Zlib), which deny.toml does not allow. The tree is 6 crates (rusqlite, libsqlite3-sys, fallible-iterator, fallible-streaming-iterator; build: pkg-config, vcpkg, plus cc already present); cargo vet exemptions recorded for them. Statements are prepared per call.

Load check again without the statement cache (release): write 4.4 s, page through all 280 ms, one tag value 1.0 ms, expiry range 19 ms, cleanup 4.1 s.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
SQLite (rusqlite, bundled) and files backends of spec/store as private ti-cli modules, selected by TI_STORE_BACKEND. Both pass spec/store's capabilities and operation scenarios from the manifest (cargo test -p ti-cli --lib store::), the SQLite one including 100,000 records. Further tests: 16 concurrent takes find a record once on both backends; concurrent creation; schema, application id, levels (STORE-070, -071, -100, -101); tags with their record; failed batch; file modes 0600/0700; the files backend never follows a link out of its root; the load check within its budget. Corrected STORE-070's decimal application id. Follow-up: TASK-113 (expiry-range index).
<!-- SECTION:FINAL_SUMMARY:END -->
