---
id: TASK-208
title: 'ti-cli, ti-store: replace the sealed store with plain files'
status: In Progress
assignee: []
created_date: '2026-11-03T19:45:00Z'
updated_date: '2026-11-03T20:20:00Z'
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

Profiles stay as plain directories; the design is in the implementation notes.
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
# Plain files instead of the sealed store: implementation plan

> For agentic workers: use superpowers:subagent-driven-development or superpowers:executing-plans, task by task. Steps use checkboxes.

**Goal:** ti keeps its cache, TSL rollback state and comfort IDs in plain files, in plain profile directories, with the sealed store, SQLite and spec/store gone.

**Architecture:** one small I/O module (`files`) for atomic and private writes, one for profile paths (`profile`), and a `CacheStore` over files (`file_cache`). The consumers in trust.rs and documents.rs move to them one at a time, each commit green; the removal comes last.

**Tech stack:** Rust, std only for the new code; serde_json and sha2 are already in ti-cli.

**Spec:** decision-14 and the design in this task's notes.

## Global constraints

- Branch `refactor/ti-cli-plain-files` from main. rust/helpers/ stays out of it.
- No new dependency and no new `unsafe`.
- Every new source file starts with the EUPL header of its neighbours. Comments explain why, and no rule numbers from spec/store remain.
- Tests are named after the requirement they prove. TSLSIG-053 stays the rule of the rollback check.
- `just check` in rust/ scoped to the changed crates per task; the full check before the pull request. Never weaken a lint.
- Commits carry no AI attribution.

## Review focus

1. A Konnektor returns an ICCSN or card handle such as `../../x`: the path stays inside the comfort directory (test in Task 4).
2. A truncated or corrupt TSL state file: an error naming the file, never a silent restart that drops rollback protection (Task 3). This replaces today's `read_legacy`, which swallows the failure.
3. A run killed during a write, or two runs at once: readers never see a partial file and ignore leftover temp files (Task 1, Task 2).
4. A state directory that cannot be written: the cache falls back to memory as today, TSL state is an error, and comfort activate fails before the card is asked (Task 3, Task 4).
5. A comfort file that is a symlink, or readable by group or others: refused on POSIX (Task 4).

---

### Task 1: files and profile modules

**Files:** create `rust/ti-cli/src/files.rs`, `rust/ti-cli/src/profile.rs`; modify `rust/ti-cli/src/lib.rs`, `rust/ti-cli/src/cli.rs`, `rust/ti-cli/src/paths.rs`.

**Produces:**
- `files::write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()>`: temp file `.<name>.<pid>.<counter>.tmp` in the same directory, opened with create_new, mode 0600 on POSIX, sync, rename.
- `files::create_private_dir(path: &Path) -> io::Result<()>`: recursive, mode 0700 for the directories it creates on POSIX.
- `files::path_component(text: &str) -> String`: `text` if it is 1 to 64 characters of `[A-Za-z0-9._-]` and does not start with `.`; otherwise the hex SHA-256 of `text`, so distinct unsafe values never share a path.
- `profile::Profile { name: Option<String>, state_dir: PathBuf, cache_dir: PathBuf }`, `Profile::resolve(global: &GlobalArgs) -> Result<Profile, CliError>`.
- `profile::validate_name(name: &str) -> Result<(), CliError>`: 1 to 64 characters of `[A-Za-z0-9._-]`, no leading `.`. No name is reserved.
- `crate::now() -> Timestamp`, replacing `store::now` for its callers.

Paths: the state base is `TI_STATE_DIR`, else `<state home>/telematik/ti`; the cache base is `--cache-dir`/`TI_CACHE_DIR`, else `<cache home>/telematik/ti`, where the homes are as `paths.rs` and the cache resolve them today, per platform. No profile: the bases themselves. A profile: `<base>/profiles/<name>`. A relative override is an error.

- [ ] Step 1: failing tests in `files.rs` and `profile.rs`: `a_written_file_is_private_and_whole`; `a_failed_write_leaves_the_old_content`; `an_unsafe_component_cannot_leave_its_directory` (`..`, `.`, `a/b`, `../x`, empty, 65 characters all map to 64 hex digits); `distinct_unsafe_components_do_not_collide` (`a/b` and `a_b`); `no_profile_uses_the_bases`; `a_profile_is_a_directory_below_the_bases`; `a_name_with_a_path_separator_is_refused` (`../x`, `a/b`, `a\b`, empty, `.x`); `default_and_fresh_are_ordinary_names`; `a_relative_state_dir_is_refused`.
- [ ] Step 2: `cargo test -p ti-cli --lib files profile`; expect a compile failure.
- [ ] Step 3: implement. On `--profile`, add `env = "TI_PROFILE"` and take the active-file default out of its help text. Declare both modules `#[doc(hidden)] pub mod` for the fuzz targets of Task 2, with the comment saying so.
- [ ] Step 4: the same command passes.
- [ ] Step 5: commit `ti-cli: profile directories and private, atomic file writes`.

### Task 2: cache as files

**Files:** create `rust/ti-cli/src/file_cache.rs`, `rust/ti-cli/fuzz/` (Cargo.toml outside the workspace as ti-store/fuzz has it, target `cache_entry`); modify `rust/ti-cli/src/trust.rs`, `rust/ti-cli/src/connector.rs`, `rust/ti-cli/src/commands/tsl.rs`, `rust/ti-cli/src/commands/cache.rs`, `rust/ti-cli/tests/schema.rs`, `rust/ti-cli/schemas/cache-clear.json`, `rust/Justfile`.

**Consumes:** `files::write_atomic`, `Profile`.

**Produces:**
- `file_cache::FileCache { dir: PathBuf }`, `FileCache::open(profile: &Profile) -> io::Result<FileCache>`, `impl CacheStore`.
- `file_cache::entry_path(dir: &Path, key: &str) -> PathBuf`: `<dir>/v1/<hex SHA-256 of key>`. Hashing keeps URL-derived keys out of the path.
- `file_cache::encode` and `decode`, moved unchanged with their format from `store/cache.rs`; `decode` is the fuzz target's entry.
- `file_cache::clear(dir: &Path) -> io::Result<u64>`: removes `v1`, returns the number of entries.

Pruning: on `put`, entries with an mtime older than 30 days are removed, the longest lifetime the namespaces had; a failure to prune is ignored. Reads never prune, so offline runs keep what they have. Freshness stays with `CachePolicy`.

`cache clear` reports `profile` (string or null), `path` and `removed_records`.

- [ ] Step 1: failing tests: `a_cache_entry_survives_a_new_process` (round trip through two `FileCache` values, `meta.source == Source::Cache`); `a_corrupt_entry_is_a_miss`; `a_leftover_temp_file_is_not_an_entry`; `concurrent_writers_leave_a_whole_entry` (8 threads, same key, then `get` returns one writer's body whole); `a_key_with_slashes_stays_below_the_cache` (`ti-pki/v1/ocsp/ab/cd`); `a_put_removes_entries_older_than_thirty_days`; `a_get_keeps_old_entries`; in `tests/cli.rs`, `cache_clear_keeps_the_tsl_state`.
- [ ] Step 2: run them; expect failure.
- [ ] Step 3: implement, and swap `Session::new` and `connector.rs:181` to `FileCache`. Change `seed_cache_db` in `tests/schema.rs` into `seed_cache` using `entry_path` and `encode`. Add the recipe `fuzz-ti-cli seconds="30"` modelled on `fuzz-ti-store`.
- [ ] Step 4: `cargo test -p ti-cli`; passes. `just fuzz-ti-cli 30`; no crash.
- [ ] Step 5: commit `ti-cli: the download cache is plain files`.

### Task 3: TSL state as a file

**Files:** modify `rust/ti-cli/src/trust.rs`, `rust/ti-cli/src/error.rs`, `rust/ti-cli/fuzz/`.

**Consumes:** `Profile`, `files::write_atomic`.

**Produces:**
- `TslStateStore` over `<state_dir>/tsl/<id>.json`, the JSON of `TslState`, with `read(&self) -> Result<Option<TslState>, CliError>` and `write(&self, &TslState) -> Result<(), CliError>`.
- `trust::parse_tsl_state(bytes: &[u8]) -> Result<TslState, serde_json::Error>`, public for the fuzz target `tsl_state`.
- `CliError::State { path: String, reason: String }`, with a hint that names the file and says removing it restarts from the next verified TSL.

A missing file is `Ok(None)`. An unreadable or malformed file, or a failed write, is `CliError::State`. The warning that names `ti profile create` goes, and so do keyring, legacy import and the version byte.

- [ ] Step 1: failing tests: `tsl_state_is_kept_without_any_setup`; `an_older_tsl_is_rejected_on_a_later_run` (TSLSIG-053, in `tests/cli.rs` if its fixtures allow, else on `TslStateStore`); `a_corrupt_tsl_state_is_an_error_naming_the_file`; `an_unwritable_state_directory_is_an_error`; `profiles_keep_separate_tsl_state`.
- [ ] Step 2: run them; expect failure.
- [ ] Step 3: implement, and remove `import_legacy`, `read_legacy` and their tests. `Session.selected` becomes `profile: Option<Profile>`.
- [ ] Step 4: `cargo test -p ti-cli`; passes. `just fuzz-ti-cli 30`; no crash.
- [ ] Step 5: commit `ti-cli: TSL state is a plain file, kept without setup`.

### Task 4: comfort IDs as private files

**Files:** modify `rust/ti-cli/src/commands/documents.rs`, `rust/ti-cli/src/connector.rs`, `rust/ti-cli/tests/connector.rs`, `rust/ti-cli/fuzz/`.

**Consumes:** `files::{write_atomic, create_private_dir, path_component}`, `CliError::State`.

**Produces:** `ComfortStore` over `<state_dir>/comfort/<path_component(konnektor)>/<path_component(card id)>`, holding the text of `ComfortUserId`. `ComfortStore::prepare(&self) -> Result<(), CliError>` replaces `require_keyring`: it creates the directory, and runs before the card is asked. Also a `read_comfort(path: &Path) -> Result<Option<ComfortUserId>, CliError>`.

On POSIX, `read_comfort` checks `symlink_metadata` first and refuses a symlink, a file with any group or other mode bit, or a directory with any such bit. Malformed content is `CliError::State`. A file left from a pre-store version is read if it passes these checks.

- [ ] Step 1: failing tests: `a_comfort_id_is_private_on_disk` (file 0600, directory 0700); `a_group_readable_comfort_file_is_refused`; `a_symlinked_comfort_file_is_refused`; `a_hostile_card_id_stays_in_the_comfort_directory` (fake Konnektor, ICCSN `../../x`; assert only paths below `comfort/` are created); `activate_fails_before_the_card_is_asked_when_state_cannot_be_written` (the fake records no card call); `profiles_keep_separate_comfort_ids`. Rewrite the tests at `tests/connector.rs:884-893` and `:943`: activate works with no `profile create`.
- [ ] Step 2: run them; expect failure.
- [ ] Step 3: implement. Remove `legacy`, `legacy_path` and `dir_name`. Gate the mode checks with `#[cfg(unix)]`; elsewhere the per-user directory protects them.
- [ ] Step 4: `cargo test -p ti-cli`; passes.
- [ ] Step 5: commit `ti-cli: comfort IDs in private files`.

### Task 5: remove the store from ti-cli

**Files:** delete `rust/ti-cli/src/store/`, `rust/ti-cli/src/commands/store.rs`, `rust/ti-cli/examples/store-interop.rs`, the schemas `store-*.json`, `profile-create`, `profile-use`, `profile-show`, `profile-rotate`, `profile-rewrap`; modify `rust/ti-cli/src/commands/profile.rs`, `commands/mod.rs`, `cli.rs`, `error.rs`, `paths.rs`, `lib.rs`, `Cargo.toml`, the schemas `profile-list.json` and `profile-delete.json`, tests that set `TI_STORE_*`, and `tests/connector.rs` (the rotate and store_json tests).

**Produces:** `ti profile list` (the unnamed location and each directory below `profiles/`, with state and cache sizes) and `ti profile delete NAME --yes` (removes `<state base>/profiles/NAME` and `<cache base>/profiles/NAME`; an unknown name is an error; validated with `validate_name` so it cannot leave `profiles/`).

- [ ] Step 1: failing tests: `profile_list_shows_the_slots_in_use`; `profile_delete_removes_state_and_cache`; `profile_delete_refuses_a_path` (`../x`); `the_old_store_files_are_not_read` (a `state.db`, `keyring.bin` and `store.kek` at the old paths leave a run unaffected and unchanged); `removed_commands_are_gone` (`ti store doctor`, `ti profile create` are usage errors).
- [ ] Step 2: run them; expect failure.
- [ ] Step 3: implement. Remove `CliError::Store`, `StoreFile`, `store_kind`, `store_hint`, every `TI_STORE_*` read and the `-v` line's store paths; print the profile and directories instead. Remove `rusqlite` and the `store` and `test-util` features from `rust/ti-cli/Cargo.toml`.
- [ ] Step 4: `cargo test -p ti-cli`, `cargo clippy -p ti-cli --all-targets`, and the schema test; all pass. `grep -rE 'TI_STORE|keyring|state\.db' rust/ti-cli/src rust/ti-cli/tests` finds only `the_old_store_files_are_not_read`.
- [ ] Step 5: commit `ti-cli: remove the sealed store and its commands`.

### Task 6: remove the store from ti-store, the workspace and the spec

**Files:** delete `rust/ti-store/src/store/`, `rust/ti-store/fuzz/`, `rust/ti-store/tests/`, `rust/ti-store/examples/conformance.rs`, `spec/store/`; modify `rust/ti-store/Cargo.toml`, `rust/ti-store/src/lib.rs`, `rust/Cargo.toml`, `rust/Cargo.lock`, `rust/Justfile` (lines 72-74 for the `/spec` mount, 384, the `fuzz-ti-store` recipe), `rust/supply-chain/`, `spec/README.md`, and any CI step `grep -rn 'spec/store\|fuzz-ti-store'` finds.

- [ ] Step 1: delete, and drop feature `store`, feature `test-util`, the optional crypto dependencies and the dev-dependencies only those tests used. Keep `ti_store::Cache` and its tests in `cache.rs`.
- [ ] Step 2: `cargo update --workspace` only as needed for the lock file; `grep -n rusqlite Cargo.lock` finds nothing; `cargo vet prune` removes the stale exemptions.
- [ ] Step 3: `cargo check -p ti-store --target wasm32-unknown-unknown` passes; `just check` in rust/ passes; `just cli-check` passes (needs Docker), proving the `/spec` mount is no longer needed.
- [ ] Step 4: `grep -rn 'spec/store\|ti_store::store' rust go docs spec --exclude-dir=target --exclude-dir=dist` finds only rust/ReleaseNotes.md history.
- [ ] Step 5: commit `Remove the sealed store, spec/store and SQLite`.

### Task 7: documents and proof

**Files:** modify `rust/ti-cli/README.md` (lines 56-59, 122-123, 240, 271-303), `rust/ti-store/README.md`, `rust/ti-store/Cargo.toml` (description), `rust/docs/design.md` (line 165), `rust/docs/unsafe-exceptions.md`, `rust/ReleaseNotes.md`, the agent guide in `rust/ti-cli/src/commands/agent.rs` if it names the store.

- [ ] Step 1: write the layout table, the two throwaway recipes (`ti --profile "$(uuidgen)" …`; `TI_STATE_DIR=$(mktemp -d) TI_CACHE_DIR=$(mktemp -d) ti …`), and that a comfort ID lies unencrypted in a private file. Under Unreleased in the release notes, record the removal of the sealed store and its commands.
- [ ] Step 2: `just check` in rust/ passes; `ti --help` and `ti profile --help` read correctly.
- [ ] Step 3: commit `Document the plain-file layout`.
- [ ] Step 4: hand the maintainer the HITL: with a real Konnektor and HBA under `--profile "$(uuidgen)"`, comfort activate, a sign without PIN, `ls -l` on the comfort file, comfort deactivate, `ti profile delete`. Wait for the maintainer's confirmation before ticking AC #4.
- [ ] Step 5: delete the old store by hand on the maintainer's machine, only when the maintainer says so: `~/.local/state/telematik/profiles`, `~/.cache/telematik/profiles`, `~/.config/telematik/profiles`.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design agreed with the maintainer on 2026-11-03. Profiles stay as plain directories: --profile NAME and TI_PROFILE choose a directory below profiles/, created on first use, with no reserved names and no remembered active profile; without a name, the bases themselves. ti profile list and delete stay; create, use, show, rotate and rewrap go, and so does ti store. Throwaway runs are left to the shell: --profile "$(uuidgen)", or TI_STATE_DIR and TI_CACHE_DIR with mktemp. Layout: <state>/tsl/<id>.json, <state>/comfort/<konnektor>/<card>, <cache>/v1/<sha256 of key>, with <state> = ~/.local/state/telematik/ti and <cache> = ~/.cache/telematik/ti. The maintainer is the only user, so nothing is migrated and old files are removed by hand.
<!-- SECTION:NOTES:END -->
