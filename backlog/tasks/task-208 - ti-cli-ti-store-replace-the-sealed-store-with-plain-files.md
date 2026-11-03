---
id: TASK-208
title: 'ti-cli, ti-store: replace the sealed store with plain files'
status: To Do
assignee: []
created_date: '2026-11-03T19:45:00Z'
updated_date: '2026-11-03T19:51:00Z'
labels:
  - ti-cli
  - ti-store
  - spec
  - deps
  - security
  - chore
dependencies: []
references:
  - >-
    backlog/decisions/decision-14 -
    Command-line-tools-keep-no-sealed-store-the-comfort-ID-in-a-private-file.md
  - spec/store/README.md
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 215000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-14 ends the sealed store for the command-line tools. The sealing no longer protects enough to justify its cost. Only two sealed namespaces are in use, comfort and tsl.state (rust/ti-cli/src/commands/documents.rs, rust/ti-cli/src/trust.rs); oauth.access, oauth.refresh and popp have no consumer. go/store and go/sqlitestore were removed in a2b2b32, and TASK-104, TASK-105, TASK-111 and TASK-115 are archived undone. The default key file lies under the same account as the records it protects (spec/store, Security considerations). The cost: about 3,000 lines in rust/ti-store/src/store, about 3,900 lines of store code in rust/ti-cli/src/store and rust/ti-cli/src/commands/{store,profile}.rs without tests, spec/store with 132 rules and its corpus, four fuzz targets and bundled C SQLite through rusqlite. It also weakens a security check: without `ti profile create` the TSL state is not kept, so an older TSL is not rejected (trust.rs TslStateStore).

ti_store::Cache and CacheStore stay; they carry the HTTP semantics and do not depend on the feature store. Existing sealed comfort IDs and TSL state are not migrated: reading them would keep the code this task removes. Comfort is activated again, and the TSL state restarts from the next verified TSL.

To settle before planning: whether --profile and TI_PROFILE stay as plain directories or go. Decide from whether profiles are used; separate Konnektor configurations already exist as .kon files.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti keeps its HTTP cache as plain files written by atomic rename; concurrent ti processes never leave a torn entry
- [ ] #2 TSL rollback state is kept on every run with a writable state directory, without any setup; an older TSL is rejected after a fresh install's first verified TSL
- [ ] #3 Each comfort ID lies in its own file: mode 0600 in a 0700 directory on POSIX; on POSIX, ti refuses a comfort file readable by group or others
- [ ] #4 comfort activate, a sign without PIN and comfort deactivate work against a real Konnektor and HBA, proven by the maintainer
- [ ] #5 No token and no other secret than the comfort ID is written to disk by ti
- [ ] #6 The feature store of ti-store, rusqlite and any crate only they need are gone from Cargo.lock and rust/supply-chain
- [ ] #7 spec/store and the store fuzz targets are removed; each new file parser has a fuzz target
- [ ] #8 Tests named after the requirement each proves cover the file layout, the mode check and TSL rollback across runs
- [ ] #9 ti store and the keyring subcommands of ti profile are gone; ti cache works on the plain files; TI_STORE_KEK_PATH and TI_STORE_BACKEND have no effect
- [ ] #10 ti no longer reads state.db, cache.db, keyring.bin or store.kek
- [ ] #11 rust/ti-cli/README.md, rust/ti-store/README.md, rust/docs/design.md, spec/README.md and the ti-cli JSON schemas describe the new layout; rust/ReleaseNotes.md records the removal of the sealed store
<!-- AC:END -->
