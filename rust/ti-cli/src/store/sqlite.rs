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

//! The SQLite backend of spec/store (section H): `state.db` and `cache.db`.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};
use ti_store::store::levels::{MAX_LEVEL, check_database};
use ti_store::store::{
    Backend, BatchOp, Capabilities, Field, Name, Namespace, Page, Query, StoreError, StoredRecord,
    Tag,
};
use ti_types::Timestamp;

/// The schema of the newest level, run as the specification gives it (STORE-071).
const SCHEMA: &str = include_str!("../../../../spec/store/schema.sql");

/// STORE-070: "ZLST".
const APPLICATION_ID: i32 = 0x5A4C_5354;

/// STORE-072: at least 5000 ms.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Which of a profile's databases, for the durability it needs (STORE-072).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Db {
    /// `state.db`: records that must survive.
    State,
    /// `cache.db`: records that may be lost.
    Cache,
}

/// One database file. A connection serves one operation at a time; other processes
/// coordinate through SQLite's locks.
#[derive(Debug)]
pub struct SqliteBackend(Mutex<Connection>);

impl SqliteBackend {
    /// Opens the database at `path`, creating it with the schema if it does not exist,
    /// and checks its format level (STORE-070, STORE-071, STORE-100, STORE-101).
    ///
    /// # Errors
    ///
    /// `malformed` for a file that is not a store database, `unsupported_version` for one
    /// a newer, incompatible tool wrote, `busy` if another process holds it past the busy
    /// timeout.
    pub fn open(path: &Path, db: Db) -> Result<Self, StoreError> {
        create_private(path)?;
        let conn = Connection::open(path).map_err(|e| sql(&e))?;
        configure(&conn, db)?;
        let backend = SqliteBackend(Mutex::new(conn));
        backend.init()?;
        Ok(backend)
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Backend("database connection lock poisoned".into()))
    }

    /// Creates the schema in a new database, or checks an existing one. Two processes may
    /// create the same database at once: the transaction looks again after taking the
    /// write lock, and the second finds the tables the first created. Switching a new
    /// database to WAL can fail as busy at once rather than wait, when two connections
    /// each hold a read lock and need the write lock; creation is then tried again until
    /// the busy timeout.
    fn init(&self) -> Result<(), StoreError> {
        let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
        loop {
            match self.create() {
                Err(StoreError::Busy) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }

    fn create(&self) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        if !has_tables(&conn)? {
            let (pragmas, body) = schema_parts();
            conn.execute_batch(pragmas).map_err(|e| sql(&e))?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| sql(&e))?;
            if !has_tables(&tx)? {
                tx.execute_batch(body).map_err(|e| sql(&e))?;
            }
            tx.commit().map_err(|e| sql(&e))?;
        }
        check_level(&conn)?;
        // A database left in another journal mode is still readable; WAL is what the
        // other tools expect (STORE-071).
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| sql(&e))?;
        Ok(())
    }

    fn tags(conn: &Connection, ns: &Namespace, name: &Name) -> Result<Vec<Tag>, StoreError> {
        let mut stmt = conn
            .prepare("SELECT field, tag FROM tags WHERE ns = ?1 AND name = ?2")
            .map_err(|e| sql(&e))?;
        let rows = stmt
            .query_map(params![ns.as_str(), &name.0[..]], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| sql(&e))?;
        rows.map(|row| {
            let (field, tag) = row.map_err(|e| sql(&e))?;
            Ok(Tag {
                field: Field::new(&field).map_err(|_| StoreError::Malformed("tag"))?,
                tag: tag.try_into().map_err(|_| StoreError::Malformed("tag"))?,
            })
        })
        .collect()
    }

    fn put_in(
        conn: &Connection,
        ns: &Namespace,
        name: &Name,
        r: &StoredRecord,
    ) -> Result<(), StoreError> {
        // the cascade removes the old record's tags (STORE-011)
        conn.prepare("DELETE FROM records WHERE ns = ?1 AND name = ?2")
            .and_then(|mut s| s.execute(params![ns.as_str(), &name.0[..]]))
            .map_err(|e| sql(&e))?;
        conn.prepare("INSERT INTO records (ns, name, value, expires_at) VALUES (?1, ?2, ?3, ?4)")
            .and_then(|mut s| {
                s.execute(params![
                    ns.as_str(),
                    &name.0[..],
                    &r.value,
                    time(r.expires_at)
                ])
            })
            .map_err(|e| sql(&e))?;
        let mut stmt = conn
            .prepare("INSERT OR IGNORE INTO tags (ns, field, tag, name) VALUES (?1, ?2, ?3, ?4)")
            .map_err(|e| sql(&e))?;
        for t in &r.tags {
            stmt.execute(params![
                ns.as_str(),
                t.field.as_str(),
                &t.tag[..],
                &name.0[..]
            ])
            .map_err(|e| sql(&e))?;
        }
        Ok(())
    }

    fn delete_in(conn: &Connection, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        conn.prepare("DELETE FROM records WHERE ns = ?1 AND name = ?2")
            .and_then(|mut s| s.execute(params![ns.as_str(), &name.0[..]]))
            .map(drop)
            .map_err(|e| sql(&e))
    }
}

impl SqliteBackend {
    /// The database's levels and the result of `PRAGMA quick_check` (STORE-123).
    ///
    /// # Errors
    ///
    /// The database's errors.
    pub fn inspect(&self) -> Result<super::Inspection, StoreError> {
        let conn = self.conn()?;
        let (_, level, min_compatible) = read_levels(&conn)?;
        let rows: Vec<String> = conn
            .prepare("PRAGMA quick_check")
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<Result<_, _>>()
            })
            .map_err(|e| sql(&e))?;
        Ok(super::Inspection {
            level,
            min_compatible,
            integrity: Some(rows.join("; ")),
        })
    }
}

impl Backend for SqliteBackend {
    fn capabilities(&self) -> Capabilities {
        // STORE-078
        Capabilities {
            atomic_take: true,
            atomic_batch: true,
            indexed: true,
            multi_process: true,
        }
    }

    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let conn = self.conn()?;
        let row = conn
            .prepare(
                "SELECT value, expires_at FROM records WHERE ns = ?1 AND name = ?2 \
                 AND (expires_at IS NULL OR expires_at > ?3)",
            )
            .and_then(|mut s| {
                s.query_row(params![ns.as_str(), &name.0[..], stamp(now)], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?))
                })
                .optional()
            })
            .map_err(|e| sql(&e))?;
        let (value, expires_at) = row.ok_or(StoreError::NotFound)?;
        Ok(StoredRecord {
            value,
            expires_at: expiry(expires_at)?,
            tags: Self::tags(&conn, ns, name)?,
        })
    }

    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError> {
        record.check()?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql(&e))?;
        Self::put_in(&tx, ns, name, &record)?;
        tx.commit().map_err(|e| sql(&e))
    }

    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql(&e))?;
        // read under the write lock, before the cascade removes them
        let tags = Self::tags(&tx, ns, name)?;
        // STORE-074: the one statement that decides which taker wins
        let row = tx
            .prepare(
                "DELETE FROM records WHERE ns = ?1 AND name = ?2 \
                 AND (expires_at IS NULL OR expires_at > ?3) RETURNING value, expires_at",
            )
            .and_then(|mut s| {
                s.query_row(params![ns.as_str(), &name.0[..], stamp(now)], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?))
                })
                .optional()
            })
            .map_err(|e| sql(&e))?;
        tx.commit().map_err(|e| sql(&e))?;
        let (value, expires_at) = row.ok_or(StoreError::NotFound)?;
        Ok(StoredRecord {
            value,
            expires_at: expiry(expires_at)?,
            tags,
        })
    }

    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql(&e))?;
        Self::delete_in(&tx, ns, name)?;
        tx.commit().map_err(|e| sql(&e))
    }

    async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError> {
        for op in &ops {
            if let BatchOp::Put(_, _, r) = op {
                r.check()?;
            }
        }
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql(&e))?;
        for op in &ops {
            match op {
                BatchOp::Put(ns, name, r) => Self::put_in(&tx, ns, name, r)?,
                BatchOp::Delete(ns, name) => Self::delete_in(&tx, ns, name)?,
            }
        }
        // dropping the transaction on an error above rolls everything back (STORE-014)
        tx.commit().map_err(|e| sql(&e))
    }

    async fn query(&self, q: &Query) -> Result<Page, StoreError> {
        q.check()?;
        let conn = self.conn()?;
        let (text, args) = query_sql(q);
        let mut stmt = conn.prepare(&text).map_err(|e| sql(&e))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|e| sql(&e))?;
        let mut records = Vec::new();
        for row in rows {
            let (name, value, expires_at) = row.map_err(|e| sql(&e))?;
            let name = Name::try_from(&name[..]).map_err(|_| StoreError::Malformed("name"))?;
            let tags = Self::tags(&conn, &q.ns, &name)?;
            records.push((
                name,
                StoredRecord {
                    value,
                    expires_at: expiry(expires_at)?,
                    tags,
                },
            ));
        }
        Ok(Page::from_matches(records, q.limit))
    }

    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
        if limit == 0 {
            return Err(StoreError::InvalidArgument("limit"));
        }
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql(&e))?;
        let removed = tx
            .prepare(
                "DELETE FROM records WHERE (ns, name) IN (SELECT ns, name FROM records \
                 WHERE expires_at IS NOT NULL AND expires_at <= ?1 LIMIT ?2)",
            )
            .and_then(|mut s| {
                s.execute(params![
                    stamp(now),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ])
            })
            .map_err(|e| sql(&e))?;
        tx.commit().map_err(|e| sql(&e))?;
        Ok(removed)
    }
}

/// The query of STORE-015 and STORE-016. With filters it starts from the first filter's
/// tag rows, which are ordered by name, so that its cost follows the matches rather than
/// the namespace.
fn query_sql(q: &Query) -> (String, Vec<rusqlite::types::Value>) {
    use std::fmt::Write as _;

    use rusqlite::types::Value;
    let mut args: Vec<Value> = vec![q.ns.as_str().to_owned().into(), stamp(q.now).into()];
    let mut text = String::from("SELECT r.name, r.value, r.expires_at FROM ");
    let mut filters = q.filters.iter();
    // ordering and paging on the driving table's name keeps SQLite on its primary key
    let mut key = "r.name";
    if let Some(first) = filters.next() {
        key = "t0.name";
        text.push_str(
            "tags t0 JOIN records r ON r.ns = t0.ns AND r.name = t0.name \
             WHERE t0.ns = ?1 AND t0.field = ?3 AND t0.tag = ?4 AND ",
        );
        args.push(first.field.as_str().to_owned().into());
        args.push(first.tag.to_vec().into());
    } else {
        text.push_str("records r WHERE r.ns = ?1 AND ");
    }
    text.push_str("(r.expires_at IS NULL OR r.expires_at > ?2)");
    for f in filters {
        let n = args.len();
        let _ = write!(
            text,
            " AND EXISTS (SELECT 1 FROM tags t WHERE t.ns = r.ns AND t.name = r.name \
             AND t.field = ?{} AND t.tag = ?{})",
            n + 1,
            n + 2
        );
        args.push(f.field.as_str().to_owned().into());
        args.push(f.tag.to_vec().into());
    }
    // a record that does not expire is later than any time (STORE-015)
    if let Some(from) = q.from {
        args.push(stamp(from).into());
        let _ = write!(
            text,
            " AND (r.expires_at IS NULL OR r.expires_at >= ?{})",
            args.len()
        );
    }
    if let Some(to) = q.to {
        args.push(stamp(to).into());
        let _ = write!(
            text,
            " AND r.expires_at IS NOT NULL AND r.expires_at < ?{}",
            args.len()
        );
    }
    if let Some(cursor) = q.cursor {
        args.push(cursor.0.to_vec().into());
        let _ = write!(text, " AND {key} > ?{}", args.len());
    }
    args.push(i64::try_from(q.limit).unwrap_or(i64::MAX).into());
    let _ = write!(text, " ORDER BY {key} LIMIT ?{}", args.len());
    (text, args)
}

/// `schema.sql` split where its transaction begins: the pragmas that must run outside a
/// transaction, and the body inside one.
fn schema_parts() -> (&'static str, &'static str) {
    let (pragmas, rest) = SCHEMA
        .split_once("BEGIN IMMEDIATE;")
        .expect("schema.sql has one transaction");
    let (body, _) = rest
        .rsplit_once("COMMIT;")
        .expect("schema.sql has one transaction");
    (pragmas, body)
}

fn has_tables(conn: &Connection) -> Result<bool, StoreError> {
    conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|n| n > 0)
    .map_err(|e| sql(&e))
}

/// STORE-070, STORE-101, STORE-100.
fn check_level(conn: &Connection) -> Result<(), StoreError> {
    let (user_version, level, min_compatible) = read_levels(conn)?;
    check_database(MAX_LEVEL, user_version, level, min_compatible)
}

/// `user_version` and the levels in `meta` of a database with the store's application id.
fn read_levels(conn: &Connection) -> Result<(u16, u16, u16), StoreError> {
    let id: i32 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|e| sql(&e))?;
    if id != APPLICATION_ID {
        return Err(StoreError::Malformed("database"));
    }
    let user_version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| sql(&e))?;
    let meta = |key: &str| -> Result<i64, StoreError> {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(|e| sql(&e))?
            .ok_or(StoreError::Malformed("database meta"))
    };
    let level16 = |v: i64| u16::try_from(v).map_err(|_| StoreError::Malformed("format level"));
    Ok((
        level16(user_version)?,
        level16(meta("level")?)?,
        level16(meta("min_compatible")?)?,
    ))
}

/// STORE-072.
fn configure(conn: &Connection, db: Db) -> Result<(), StoreError> {
    conn.busy_timeout(BUSY_TIMEOUT).map_err(|e| sql(&e))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| sql(&e))?;
    let (synchronous, secure_delete) = match db {
        Db::State => ("FULL", "ON"),
        Db::Cache => ("NORMAL", "OFF"),
    };
    conn.pragma_update(None, "synchronous", synchronous)
        .map_err(|e| sql(&e))?;
    conn.pragma_update(None, "secure_delete", secure_delete)
        .map_err(|e| sql(&e))?;
    Ok(())
}

/// STORE-077: the file exists with mode 0600 before SQLite opens it; SQLite gives the
/// `-wal` and `-shm` files the database's mode.
fn create_private(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .map(drop)
        .map_err(|e| StoreError::Backend(format!("{}: {e}", path.display())))
}

/// Times fit in an `i64`: STORE-002 bounds them far below.
fn stamp(t: Timestamp) -> i64 {
    i64::try_from(t.0).unwrap_or(i64::MAX)
}

fn time(t: Option<Timestamp>) -> Option<i64> {
    t.map(stamp)
}

fn expiry(v: Option<i64>) -> Result<Option<Timestamp>, StoreError> {
    v.map(|v| {
        u64::try_from(v)
            .ok()
            .filter(|&v| v > 0)
            .map(Timestamp)
            .ok_or(StoreError::Malformed("expiry"))
    })
    .transpose()
}

/// STORE-073: a lock held past the busy timeout is `busy`; a file that is not a database
/// is `malformed`.
fn sql(e: &rusqlite::Error) -> StoreError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Busy,
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => {
            StoreError::Malformed("database")
        }
        _ => StoreError::Backend(e.to_string()),
    }
}
