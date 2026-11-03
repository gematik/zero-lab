---
id: decision-14
title: Command-line tools keep no sealed store, the comfort ID in a private file
date: '2026-11-03T19:45:00Z'
status: accepted
---

## Context

Decision-7 persisted tokens and other secrets only as sealed records under a profile keyring, shared by the Go and Rust tools. Its premises have gone:

- No tool persists a token: TASK-105 is archived undone, and `oauth.access`, `oauth.refresh` and `popp` have no consumer. Only `comfort` and `tsl.state` are sealed in use.
- The tools no longer share a store: `go/store` and `go/sqlitestore` were removed in a2b2b32, and TASK-111 (JVM) and TASK-115 (zero-epa) are archived undone.
- Hardware-held keys never came: TASK-104 is archived undone. The default key file lies under the same account as the records, so sealing helps only when the state directory is copied without the configuration directory.

The store costs about 7,000 lines of Rust, `spec/store`, four fuzz targets and bundled C SQLite. It also weakens a check: without `ti profile create`, TSL rollback state is not kept, so an older TSL is not rejected.

## Decision

1. The command-line tools keep no sealed store. `spec/store`, the feature `store` of `ti-store` and ti's SQLite backend go; TASK-208 does the work.
2. Tools persist no tokens: a token lives as long as the process that fetched it, as TASK-30 decided. A refresh token kept on disk needs a new decision and a key the platform or hardware holds, not a key file and not a format of our own.
3. A comfort ID is stored in a file of its own, mode 0600 in a directory of mode 0700 on POSIX, like the secrets a `.kon` file already holds. It is the one secret kept on disk, and it is accepted there because signing with it also takes access to the Konnektor and an enabled comfort session.
4. TSL rollback state is a plain file, written without any setup. It is not secret. In the default layout, whoever can write it under the user's account could already read the key file that sealed it.
5. Downloaded material is cached in plain files. Its consumers verify it on every read, as before.

This supersedes decision-7. Servers are not affected: `go/kv` has its own rules for stored records (TASK-71).

## Consequences

- A comfort ID lies unencrypted on disk, so a backup or copy of the state directory exposes it; before, that copy also needed the configuration directory. This is accepted knowingly and revisited when a platform key store is taken up.
- Every run that needs a token logs in again, with its card or Konnektor round trip.
- Sealed comfort IDs and TSL state of existing profiles are not migrated. Comfort is activated again, and the TSL state restarts from the next verified TSL.
- Per-record binding, expiry sealed into the record, blind-index tags, `take` across processes and destroying a profile by removing its keyring all go with the store.
