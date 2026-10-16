/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The backends against spec/store's corpus and the rules a corpus cannot show: several
//! connections and processes, file modes, links, foreign databases.

#[path = "../../../ti-store/tests/conformance/eval.rs"]
#[allow(dead_code, reason = "shared with ti-store, which uses all of it")]
mod eval;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use futures_lite::future::block_on;
use serde_json::Value;
use ti_store::store::{
    Backend, BatchOp, Field, Name, Namespace, Query, StoreError, StoredRecord, Tag,
};
use ti_types::Timestamp;

use super::{AnyBackend, Db, FilesBackend, Kind, SqliteBackend};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ti-store-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fresh backend in its own directory for each scenario.
#[derive(Default)]
struct Fresh(RefCell<Vec<TempDir>>);

impl eval::Backends for Fresh {
    type B = AnyBackend;
    fn fresh(&self, name: &str) -> Option<AnyBackend> {
        let dir = TempDir::new(name);
        let backend = match name {
            "sqlite" => AnyBackend::open(Kind::Sqlite, &dir.0.join("state.db"), Db::State),
            "files" => AnyBackend::open(Kind::Files, &dir.0.join("state"), Db::State),
            _ => return None,
        }
        .expect("open a fresh backend");
        self.0.borrow_mut().push(dir);
        Some(backend)
    }
}

/// Runs the cases of `kinds` for one backend; fails with every case that disagrees, and
/// if there is none at all.
fn check(kinds: &[&str], backend: &str) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/store/testdata/manifest.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let manifest: Value = serde_json::from_str(&text).expect("manifest is JSON");
    let mut ran = 0;
    let mut failures = Vec::new();
    for c in manifest["cases"].as_array().expect("cases") {
        let kind = c["kind"].as_str().expect("kind");
        if !kinds.contains(&kind) || c["input"]["backend"].as_str() != Some(backend) {
            continue;
        }
        ran += 1;
        let id = c["id"].as_str().expect("id");
        let fresh = Fresh::default();
        let (code, output) = eval::evaluate(kind, &c["input"], &fresh)
            .unwrap_or_else(|e| panic!("{id}: broken case: {}", e.0));
        let want_code = c["expect"]["code"].as_str().expect("code");
        let want = c["expect"]
            .get("output")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if code != want_code {
            failures.push(format!("{id}: {code}, want {want_code}"));
        } else if code == "ok" && output != want {
            failures.push(format!("{id}: output\n  got  {output}\n  want {want}"));
        }
    }
    assert!(ran > 0, "no cases of kinds {kinds:?} for {backend}");
    assert!(
        failures.is_empty(),
        "{} of {ran} cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// STORE-078; STORE-010 to STORE-017 on the SQLite backend, including 100,000 records.
#[test]
fn store_078_sqlite_backend_passes_the_operation_scenarios() {
    check(&["capabilities", "scenario"], "sqlite");
}

/// STORE-084; STORE-010 to STORE-017 on the files backend.
#[test]
fn store_084_files_backend_passes_the_operation_scenarios() {
    check(&["capabilities", "scenario"], "files");
}

fn ns(s: &str) -> Namespace {
    Namespace::new(s).expect("namespace")
}

fn name(i: u32) -> Name {
    let mut n = [0u8; 32];
    n[28..].copy_from_slice(&i.to_be_bytes());
    Name(n)
}

fn record(value: &[u8], expires_at: Option<u64>) -> StoredRecord {
    StoredRecord {
        value: value.to_vec(),
        expires_at: expires_at.map(Timestamp),
        tags: Vec::new(),
    }
}

/// Opens `n` independent backends on the same files, as `n` processes would.
fn open_many(kind: Kind, path: &Path, n: usize) -> Vec<AnyBackend> {
    (0..n)
        .map(|_| AnyBackend::open(kind, path, Db::State).expect("open"))
        .collect()
}

/// Runs one `take` of the same record on each backend at once and counts the winners.
fn racing_takes(backends: Vec<AnyBackend>) -> usize {
    let barrier = Arc::new(Barrier::new(backends.len()));
    let handles: Vec<_> = backends
        .into_iter()
        .map(|b| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                match block_on(b.take(&ns("popp"), &name(1), Timestamp(10))) {
                    Ok(r) => {
                        assert_eq!(r.value, b"once");
                        1
                    }
                    Err(StoreError::NotFound) => 0,
                    Err(e) => panic!("take: {e}"),
                }
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().expect("thread")).sum()
}

/// STORE-012, STORE-074: of 16 connections taking one record at once, exactly one gets it.
#[test]
fn store_012_sqlite_concurrent_takes_return_the_record_once() {
    let dir = TempDir::new("take-sqlite");
    let path = dir.0.join("state.db");
    let backends = open_many(Kind::Sqlite, &path, 16);
    block_on(backends[0].put(&ns("popp"), &name(1), record(b"once", None))).expect("put");
    assert_eq!(racing_takes(backends), 1);
}

/// STORE-012, STORE-082: the same on the files backend.
#[test]
fn store_012_files_concurrent_takes_return_the_record_once() {
    let dir = TempDir::new("take-files");
    let root = dir.0.join("state");
    let backends = open_many(Kind::Files, &root, 16);
    block_on(backends[0].put(&ns("popp"), &name(1), record(b"once", None))).expect("put");
    assert_eq!(racing_takes(backends), 1);
}

/// STORE-071: processes that create the same new database at once all open it.
#[test]
fn store_071_concurrent_creation_of_one_database_succeeds() {
    let dir = TempDir::new("create");
    let path = Arc::new(dir.0.join("state.db"));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (path, barrier) = (Arc::clone(&path), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                SqliteBackend::open(&path, Db::State).map(drop)
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread").expect("open");
    }
}

/// STORE-071, STORE-072: a new database is incremental-vacuum and WAL, with the schema's
/// tables.
#[test]
fn store_071_new_database_is_created_from_the_schema() {
    let dir = TempDir::new("schema");
    let path = dir.0.join("cache.db");
    drop(SqliteBackend::open(&path, Db::Cache).expect("open"));
    let conn = rusqlite::Connection::open(&path).expect("raw open");
    let pragma = |p: &str| -> i64 { conn.pragma_query_value(None, p, |r| r.get(0)).expect(p) };
    assert_eq!(pragma("application_id"), 0x5A4C_5354);
    assert_eq!(pragma("user_version"), 1);
    assert_eq!(pragma("auto_vacuum"), 2, "incremental");
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .expect("journal_mode");
    assert_eq!(mode, "wal");
}

/// STORE-070: a database of another application is `malformed`, and is left as it is.
#[test]
fn store_070_another_application_id_is_malformed() {
    let dir = TempDir::new("foreign");
    let path = dir.0.join("state.db");
    let conn = rusqlite::Connection::open(&path).expect("raw open");
    conn.execute_batch("CREATE TABLE other (x); INSERT INTO other VALUES (1);")
        .expect("foreign schema");
    drop(conn);
    let err = SqliteBackend::open(&path, Db::State).expect_err("foreign database");
    assert_eq!(err.code(), "malformed");
    let conn = rusqlite::Connection::open(&path).expect("raw open");
    let n: i64 = conn
        .query_row("SELECT count(*) FROM other", [], |r| r.get(0))
        .expect("untouched");
    assert_eq!(n, 1);
}

/// STORE-070: a file that is not a database at all is `malformed`.
#[test]
fn store_070_a_file_that_is_not_a_database_is_malformed() {
    let dir = TempDir::new("garbage");
    let path = dir.0.join("state.db");
    std::fs::write(&path, [0x5a; 4096]).expect("write");
    let err = SqliteBackend::open(&path, Db::State).expect_err("garbage");
    assert_eq!(err.code(), "malformed");
}

fn set_levels(path: &Path, user_version: i64, level: i64, min_compatible: i64) {
    let conn = rusqlite::Connection::open(path).expect("raw open");
    conn.execute_batch(&format!(
        "PRAGMA user_version = {user_version};
         UPDATE meta SET value = {level} WHERE key = 'level';
         UPDATE meta SET value = {min_compatible} WHERE key = 'min_compatible';"
    ))
    .expect("set levels");
}

/// STORE-100, STORE-101: a newer compatible level opens, a newer incompatible one is
/// `unsupported_version`, levels that disagree are `malformed`.
#[test]
fn store_100_database_levels_open_as_specified() {
    let dir = TempDir::new("levels");
    let path = dir.0.join("state.db");
    drop(SqliteBackend::open(&path, Db::State).expect("create"));

    set_levels(&path, 2, 2, 1);
    SqliteBackend::open(&path, Db::State).expect("newer, compatible");

    set_levels(&path, 2, 2, 2);
    let err = SqliteBackend::open(&path, Db::State).expect_err("newer, incompatible");
    assert_eq!(err.code(), "unsupported_version");

    set_levels(&path, 1, 2, 1);
    let err = SqliteBackend::open(&path, Db::State).expect_err("levels disagree");
    assert_eq!(err.code(), "malformed");
}

/// STORE-086, STORE-100: the files tree's level, as written and as checked.
#[test]
fn store_086_files_tree_levels_open_as_specified() {
    let dir = TempDir::new("files-levels");
    let root = dir.0.join("state");
    drop(FilesBackend::open(&root).expect("create"));
    assert_eq!(
        std::fs::read(root.join("meta")).expect("meta"),
        b"ZLFM\x00\x01\x00\x01"
    );
    std::fs::write(root.join("meta"), b"ZLFM\x00\x02\x00\x02").expect("write");
    let err = FilesBackend::open(&root).expect_err("newer, incompatible");
    assert_eq!(err.code(), "unsupported_version");
}

/// STORE-011, STORE-075: replacing a record replaces its tags; deleting removes them.
#[test]
fn store_075_tags_go_with_their_record() {
    let dir = TempDir::new("tags");
    let b = SqliteBackend::open(&dir.0.join("state.db"), Db::State).expect("open");
    let tag = |v: u8| Tag {
        field: Field::new("patient").expect("field"),
        tag: [v; 32],
    };
    let query = |t: Tag| Query {
        ns: ns("popp"),
        filters: vec![t],
        from: None,
        to: None,
        limit: 10,
        cursor: None,
        now: Timestamp(1),
    };
    let mut r = record(b"v", None);
    r.tags = vec![tag(1)];
    block_on(b.put(&ns("popp"), &name(1), r.clone())).expect("put");
    r.tags = vec![tag(2)];
    block_on(b.put(&ns("popp"), &name(1), r)).expect("replace");
    assert!(
        block_on(b.query(&query(tag(1))))
            .expect("q")
            .records
            .is_empty()
    );
    assert_eq!(
        block_on(b.query(&query(tag(2)))).expect("q").records.len(),
        1
    );
    block_on(b.delete(&ns("popp"), &name(1))).expect("delete");
    let conn = rusqlite::Connection::open(dir.0.join("state.db")).expect("raw open");
    let n: i64 = conn
        .query_row("SELECT count(*) FROM tags", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 0);
}

/// STORE-014: a batch whose last operation fails applies none of them.
#[test]
fn store_014_failed_batch_applies_nothing() {
    let dir = TempDir::new("batch");
    let b = SqliteBackend::open(&dir.0.join("state.db"), Db::State).expect("open");
    let err = block_on(b.batch(vec![
        BatchOp::Put(ns("popp"), name(1), record(b"a", None)),
        BatchOp::Put(ns("popp"), name(2), record(b"b", Some(0))),
    ]))
    .expect_err("expiry 0 is invalid");
    assert_eq!(err.code(), "invalid_argument");
    let got = block_on(b.get(&ns("popp"), &name(1), Timestamp(1)));
    assert_eq!(got, Err(StoreError::NotFound));
}

/// STORE-131: `TI_STORE_BACKEND` takes `sqlite` and `files` and nothing else.
#[test]
fn store_131_backend_selection_accepts_only_sqlite_and_files() {
    assert_eq!(Kind::from_env(None), Ok(Kind::Sqlite));
    assert_eq!(Kind::from_env(Some("")), Ok(Kind::Sqlite));
    assert_eq!(Kind::from_env(Some("sqlite")), Ok(Kind::Sqlite));
    assert_eq!(Kind::from_env(Some("files")), Ok(Kind::Files));
    assert_eq!(
        Kind::from_env(Some("Files")).map_err(|e| e.code()),
        Err("invalid_argument")
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777
    }

    /// STORE-077: the database and its WAL and shared-memory files are 0600.
    #[test]
    fn store_077_database_files_are_private() {
        let dir = TempDir::new("modes-sqlite");
        let path = dir.0.join("state.db");
        let b = SqliteBackend::open(&path, Db::State).expect("open");
        block_on(b.put(&ns("popp"), &name(1), record(b"v", None))).expect("put");
        for f in ["state.db", "state.db-wal", "state.db-shm"] {
            assert_eq!(mode(&dir.0.join(f)), 0o600, "{f}");
        }
    }

    /// STORE-085: record files 0600, directories 0700.
    #[test]
    fn store_085_files_and_directories_are_private() {
        let dir = TempDir::new("modes-files");
        let root = dir.0.join("state");
        let b = FilesBackend::open(&root).expect("open");
        block_on(b.put(&ns("popp"), &name(1), record(b"v", None))).expect("put");
        let mut path = root.join("v1");
        assert_eq!(mode(&path), 0o700);
        for part in ["popp", "00", "00"] {
            path.push(part);
            assert_eq!(mode(&path), 0o700, "{}", path.display());
        }
        let file = path.join(format!("{}01.rec", "00".repeat(31)));
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&root.join("meta")), 0o600);
    }

    /// The files backend never follows a link below its root: a namespace directory
    /// linked elsewhere, or a record file linked to another file, is an error, and the
    /// file outside stays as it was.
    #[test]
    fn files_backend_does_not_follow_links_out_of_its_root() {
        let dir = TempDir::new("links");
        let root = dir.0.join("state");
        let outside = dir.0.join("outside");
        let b = FilesBackend::open(&root).expect("open");

        // a record written elsewhere, reached through a linked namespace
        let other = FilesBackend::open(&outside).expect("open outside");
        block_on(other.put(&ns("popp"), &name(1), record(b"secret", None))).expect("put");
        std::fs::create_dir(root.join("v1")).expect("v1");
        symlink(
            outside.join("v1").join("popp"),
            root.join("v1").join("popp"),
        )
        .expect("link");
        let now = Timestamp(1);
        for result in [
            block_on(b.get(&ns("popp"), &name(1), now)).map(drop),
            block_on(b.take(&ns("popp"), &name(1), now)).map(drop),
            block_on(b.put(&ns("popp"), &name(1), record(b"x", None))),
        ] {
            assert_eq!(result.map_err(|e| e.code()), Err("backend_error"));
        }
        assert_eq!(
            block_on(other.get(&ns("popp"), &name(1), now))
                .expect("outside")
                .value,
            b"secret"
        );

        // a record file that is a link to a file elsewhere
        let target = dir.0.join("victim");
        std::fs::write(&target, b"not a record").expect("write");
        block_on(b.put(&ns("oauth.access"), &name(2), record(b"v", None))).expect("put");
        let rec = root
            .join("v1/oauth.access/00/00")
            .join(format!("{}02.rec", "00".repeat(31)));
        std::fs::remove_file(&rec).expect("remove");
        symlink(&target, &rec).expect("link");
        assert_eq!(
            block_on(b.get(&ns("oauth.access"), &name(2), now)).map_err(|e| e.code()),
            Err("backend_error")
        );
        assert_eq!(
            block_on(b.take(&ns("oauth.access"), &name(2), now)).map_err(|e| e.code()),
            Err("backend_error")
        );
        assert_eq!(std::fs::read(&target).expect("victim"), b"not a record");
    }
}

/// TASK-103.4 load check: 100,000 records of 400 bytes with a tag each in `state.db`.
/// Writing in batches, paging through all of them, a tag query, an expiry range and
/// cleaning them all up stay within the budget recorded in the task, measured on a
/// debug build so that the test catches a lost index rather than a slow machine.
#[test]
fn store_016_sqlite_load_100k_records_within_budget() {
    use std::time::{Duration, Instant};
    const N: u32 = 100_000;
    let dir = TempDir::new("load");
    let b = SqliteBackend::open(&dir.0.join("state.db"), Db::State).expect("open");
    let field = Field::new("patient").expect("field");
    let popp = ns("popp");
    let mut timings = Vec::new();
    let mut lap = |what: &'static str, start: Instant| timings.push((what, start.elapsed()));

    let start = Instant::now();
    for chunk in (0..N).collect::<Vec<_>>().chunks(1000) {
        let ops = chunk
            .iter()
            .map(|&i| {
                let mut tag = [0u8; 32];
                tag[..4].copy_from_slice(&(i % 1000).to_be_bytes());
                BatchOp::Put(
                    popp.clone(),
                    name(i),
                    StoredRecord {
                        value: vec![0xa5; 400],
                        expires_at: Some(Timestamp(1000 + u64::from(i))),
                        tags: vec![Tag {
                            field: field.clone(),
                            tag,
                        }],
                    },
                )
            })
            .collect();
        block_on(b.batch(ops)).expect("batch");
    }
    lap("write 100 batches of 1000", start);

    let query = |filters: Vec<Tag>, from: Option<u64>, to: Option<u64>, cursor| Query {
        ns: popp.clone(),
        filters,
        from: from.map(Timestamp),
        to: to.map(Timestamp),
        limit: 1000,
        cursor,
        now: Timestamp(1),
    };
    let start = Instant::now();
    let (mut seen, mut cursor) = (0, None);
    loop {
        let page = block_on(b.query(&query(Vec::new(), None, None, cursor))).expect("page");
        seen += page.records.len();
        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, N as usize);
    lap("page through all", start);

    let start = Instant::now();
    let mut tag = [0u8; 32];
    tag[..4].copy_from_slice(&7u32.to_be_bytes());
    let page =
        block_on(b.query(&query(vec![Tag { field, tag }], None, None, None))).expect("tag query");
    assert_eq!(page.records.len(), 100);
    // from the tags table's key, not a walk of the namespace: well under a millisecond in
    // a release build, over 50 ms when the walk comes back
    assert!(
        start.elapsed() < Duration::from_millis(50),
        "{:?}",
        start.elapsed()
    );
    lap("one tag value", start);

    let start = Instant::now();
    let page = block_on(b.query(&query(Vec::new(), Some(51_000), Some(51_500), None)))
        .expect("range query");
    assert_eq!(page.records.len(), 500);
    lap("expiry range", start);

    let start = Instant::now();
    let mut removed = 0;
    loop {
        let n = block_on(b.cleanup(Timestamp(u64::MAX >> 1), 1000)).expect("cleanup");
        if n == 0 {
            break;
        }
        removed += n;
    }
    assert_eq!(removed, N as usize);
    lap("clean up all", start);

    for (what, took) in &timings {
        eprintln!("{what}: {took:?}");
    }
    let budget = Duration::from_secs(60);
    let total: Duration = timings.iter().map(|(_, t)| *t).sum();
    assert!(total < budget, "{total:?} over the budget of {budget:?}");
}
