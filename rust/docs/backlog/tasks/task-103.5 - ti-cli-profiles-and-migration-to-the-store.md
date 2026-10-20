---
id: TASK-103.5
title: 'ti-cli: profiles and migration to the store'
status: In Progress
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-20 08:27'
labels:
  - ti-cli
dependencies:
  - TASK-103.4
parent_task_id: TASK-103
priority: medium
ordinal: 106000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
--profile, TI_PROFILE, active file; ti profile list|use|create|delete|show; FileCacheStore replaced by a CacheStore adapter over cache.db; TSL rollback state and comfort store moved into state.db (comfort sealed); old state imported once.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 profiles resolve as STORE-7xx
- [ ] #2 ti cache clear empties the profile's cache.db
- [ ] #3 TslStateFile and ComfortStore removed; their data migrated
- [ ] #4 ti implements spec/store section L: profile create/list/use/delete/rotate/rekey/rewrap, store doctor (--deep, --json), ls/show --reveal/rm/purge, cleanup, migrate --dry-run, TI_STORE_TRACE, TI_STORE_BACKEND, hints in error messages
- [ ] #5 HITL: a throwaway profile under TI_STATE_DIR/TI_CACHE_DIR/TI_STORE_KEK_PATH is created, used for a login, checked with store doctor and deleted, proven by the user
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Three stages, each ending with a HITL run the maintainer proves:
1. Profile resolution (--profile, TI_PROFILE, active file) and STORE-092/093 paths; FileCacheStore replaced by a CacheStore adapter over cache.db (versioned payload: metadata plus body); ti cache clear empties the profile's cache.db; TslStateFile and ComfortStore into sealed state.db namespaces, old files imported once a keyring exists (until then untouched, with a warning and the profile create hint); the old cache folder is ignored. TI_CACHE_DIR/--cache-dir take the spec's meaning (shared base).
2. profile create/list/use/delete/show, store doctor (--json), TI_STORE_TRACE, hints in error messages.
3. store ls/show --reveal/rm/purge/cleanup/migrate --dry-run, profile rotate/rekey/rewrap, doctor --deep.
Decisions (maintainer, 2026-10-20): the store's --profile is global as STORE-091 says; pki verify's validation profile becomes --validation-profile, no alias (ti's flags are not released as stable). AC 5's "used for a login" is proven with pki verify / tsl show and a comfort ID, since tokens are persisted only from TASK-105.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Stage 1 implemented (2026-10-20), just check green, awaiting the maintainer's HITL:
- profile resolution and paths from ti_store::store::profile (ti-cli/src/store/profile.rs: Selected), --profile global, --cache-dir/TI_CACHE_DIR as the shared base; pki verify --validation-profile.
- cache: StoreCache (ti-cli/src/store/cache.rs) maps ti-pki and ti-connector keys onto pki.tsl, pki.roots, pki.ocsp, connector.sds; payload u8 1, u32 len, metadata JSON, body; records expire with the namespace's max_ttl. A cache that does not open (malformed, unsupported_version) is moved to cache.db.broken-<time> (STORE-128). FileCacheStore removed.
- cache clear empties the cache namespaces (query + delete) and reports removed_records.
- TSL state and comfort IDs in sealed tsl.state and comfort; without a keyring legacy files are read only and a warning names profile create; with one they are imported and removed. comfort activate refuses without a keyring before the card is asked. A state.db or keyring that does not open is an error naming file and code.
- profile create (moved into stage 1: nothing else can make a keyring): key file 0600 unless it exists or --kek-file, keyring.bin 0600, state.db and cache.db; refuses a second time.
- CliError::Store with kinds store_<code> and the section L hints.
- Tests: the fixture TSL's NextUpdate has passed, so TSL state is tested at unit level (trust.rs tests with store::profile::tests::TestProfile); integration tests seed cache.db with rusqlite and spec/store's schema, and every harness sets TI_PROFILE=default and removes the store variables.

Stage 1 HITL confirmed by the maintainer (2026-10-20) in a throwaway store: no-keyring warning, profile create, TSL state kept and read back sealed, cache clear, invalid profile name, files backend. Not yet proven: comfort activate/sign against a real Konnektor (none at hand); to repeat in a later HITL.
<!-- SECTION:NOTES:END -->
