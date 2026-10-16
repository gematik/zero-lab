---
id: TASK-103
title: 'Store: shared sealed persistence for the Go and Rust CLIs'
status: In Progress
assignee: []
created_date: '2026-10-15 17:44'
updated_date: '2026-10-16 06:53'
labels:
  - go
  - ti-cli
  - spec
  - keys
  - security
dependencies: []
references:
  - docs/design/keys.md
  - docs/architecture.md
  - docs/interop.md
  - docs/conventions/dependencies.md
priority: medium
ordinal: 101000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The CLIs (Rust ti, Go zero-epa) need many small, short-lived records shared between both languages and queryable by type and metadata: .well-known documents, OAuth access and refresh tokens, PoPP tokens. Today ti writes two files per key without locking, index or query (ti-cli/src/cache.rs), state files sit beside it (trust.rs TslStateFile, commands/documents.rs ComfortStore), and the Go CLIs persist nothing. Design: one contract spec/store (backend semantics, sealed AEAD envelope with HMAC-hashed keys and blind-index tags, keyring file, SQLite schema, profile layout), pluggable Backend/Sealer/Keyring/Store layers, SQLite as default engine, files only for inputs and as a zero-dependency fallback, per-profile state.db/cache.db/keyring.bin. Servers (go/kv on Postgres) are out of scope. Plan in the implementation plan of this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/store with corpus and generator exists, both languages pass it
- [ ] #2 sealed namespaces refuse to write without a keyring; nothing secret reaches disk unsealed
- [ ] #3 profiles switch with --profile / TI_PROFILE / active file; deleting a profile makes its data unreadable
- [ ] #4 Go and Rust share one profile's store: a record written by one is read by the other (interop matrix, TASK-103.8)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Full plan: /Users/serg/.claude/plans/persistence-layer-for-go-typed-scott.md is the working copy; the binding parts move into spec/store (TASK-103.1). Order: 103.1 spec and corpus -> 103.2 ti-base merge -> 103.3 ti_base::store -> 103.6 go/store -> dependency approvals (rusqlite bundled; ncruces/go-sqlite3 or modernc) -> 103.4, 103.7 SQLite backends -> 103.5 ti-cli profiles -> 103.8 interop matrix. JVM (zeta-cli, Kotlin/Java) is a third implementation of the contract; its constraints are folded into the spec before the corpus is fixed.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Packaging changed (2026-10-15): ti-types stays as documented; ti-cache is renamed to ti-store, which also receives the store module (TASK-103.2, 103.3). Where the plan above says ti-base, read ti-store.

zero-epa's profiles and commands are TASK-115, parked: the maintainer leaves zero-epa alone for now; the cross-language criterion is proven through the interop matrix instead.
<!-- SECTION:NOTES:END -->
