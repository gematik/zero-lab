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

//! `ti store …` (spec/store section L): checking and maintaining a profile's store.

use std::path::Path;

use serde::Serialize;
use ti_store::store::levels::MAX_LEVEL;
use ti_store::store::registry::{self, Database};
use ti_store::store::{
    Backend as _, KeyFileWrapper, Keyring, KeyringFile, Namespace, OsRandom, Query, StoreError,
};
use ti_types::Timestamp;

use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA, Tone};
use crate::store::profile::{Selected, read_kek};
use crate::store::{AnyBackend, Db, Kind, Traced, now};

/// A key older than this is due for `profile rotate` (STORE-058).
const KEY_MAX_AGE_DAYS: u64 = 365;

/// One check's outcome (STORE-123).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Serialize)]
struct Outcome {
    check: &'static str,
    status: Status,
    detail: String,
}

#[derive(Serialize)]
struct NamespaceCount {
    namespace: &'static str,
    database: &'static str,
    records: u64,
    expired: u64,
}

#[derive(Serialize)]
struct DoctorReport {
    schema: u32,
    profile: String,
    /// Where the name came from: option, env, active_file or default.
    from: &'static str,
    backend: &'static str,
    key_file: String,
    keyring: String,
    state: String,
    cache: String,
    /// The worst status of the checks.
    status: Status,
    checks: Vec<Outcome>,
    namespaces: Vec<NamespaceCount>,
}

struct Doctor {
    checks: Vec<Outcome>,
    namespaces: Vec<NamespaceCount>,
}

impl Doctor {
    fn add(&mut self, check: &'static str, status: Status, detail: impl Into<String>) {
        self.checks.push(Outcome {
            check,
            status,
            detail: detail.into(),
        });
    }
}

/// `ti store doctor`: checks the profile in effect without changing it (STORE-123).
pub fn doctor(global: &GlobalArgs, json: bool, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let profile = &selected.profile;
    let mut d = Doctor {
        checks: Vec::new(),
        namespaces: Vec::new(),
    };
    d.add(
        "profile",
        Status::Ok,
        format!("{} (from {})", profile.name, profile.from.as_str()),
    );
    let has_keyring = selected.has_keyring();
    let kek = check_key_file(&mut d, &profile.kek_file, has_keyring);
    check_keyring(&mut d, &profile.keyring, kek);
    for (db, label, path) in [
        (Db::State, "state", selected.state_path()),
        (Db::Cache, "cache", selected.cache_path()),
    ] {
        check_database(&mut d, &selected, db, label, path);
    }
    let status = d
        .checks
        .iter()
        .map(|c| c.status)
        .max()
        .unwrap_or(Status::Ok);
    let report = DoctorReport {
        schema: SCHEMA,
        profile: profile.name.clone(),
        from: profile.from.as_str(),
        backend: match selected.kind {
            Kind::Sqlite => "sqlite",
            Kind::Files => "files",
        },
        key_file: profile.kek_file.clone(),
        keyring: profile.keyring.clone(),
        state: selected.state_path().to_owned(),
        cache: selected.cache_path().to_owned(),
        status,
        checks: d.checks,
        namespaces: d.namespaces,
    };
    let exit = if status == Status::Fail {
        Exit::Invalid
    } else {
        Exit::Ok
    };
    if json || out.is_json() {
        out.json(&report)?;
        return Ok(exit);
    }
    let mut doc = Document::default();
    doc.section(format!("Store of profile {}", report.profile));
    doc.field("backend", Line::text(report.backend));
    doc.field("key file", Line::code(&report.key_file));
    doc.field("keyring", Line::code(&report.keyring));
    doc.field("state", Line::code(&report.state));
    doc.field("cache", Line::code(&report.cache));
    doc.section("Checks");
    for c in &report.checks {
        let tone = match c.status {
            Status::Ok => Tone::Good,
            Status::Warn => Tone::Warn,
            Status::Fail => Tone::Bad,
        };
        let word = match c.status {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        };
        doc.field(
            c.check,
            Line::status(tone, word).and_text(format!("  {}", c.detail)),
        );
    }
    if !report.namespaces.is_empty() {
        doc.section("Records");
        doc.table(
            &["namespace", "database", "records", "expired"],
            report
                .namespaces
                .iter()
                .map(|n| {
                    vec![
                        Line::code(n.namespace),
                        Line::text(n.database),
                        Line::text(n.records.to_string()),
                        Line::text(n.expired.to_string()),
                    ]
                })
                .collect(),
        );
    }
    out.render(&doc)?;
    Ok(exit)
}

/// Found, its mode, and that it parses (STORE-094); the key if it does.
fn check_key_file(
    d: &mut Doctor,
    path: &str,
    has_keyring: bool,
) -> Option<KeyFileWrapper<OsRandom>> {
    match read_kek(Path::new(path)) {
        Ok(kek) => {
            d.add("key_file", Status::Ok, "found, owner-only, a store key");
            Some(KeyFileWrapper::new(kek, OsRandom))
        }
        Err(StoreError::NotFound) if !has_keyring => {
            d.add(
                "key_file",
                Status::Warn,
                "not found: sealed records (tokens, TSL state, comfort IDs) are not kept until ti profile create",
            );
            None
        }
        Err(StoreError::NotFound) => {
            d.add(
                "key_file",
                Status::Fail,
                "not found, but the profile has a keyring: set TI_STORE_KEK_PATH to its key file; losing it loses only the sealed records",
            );
            None
        }
        Err(StoreError::InsecurePermissions) => {
            d.add(
                "key_file",
                Status::Fail,
                format!("readable by others: run chmod 600 {path}"),
            );
            None
        }
        Err(e) => {
            d.add("key_file", Status::Fail, format!("{}: {e}", e.code()));
            None
        }
    }
}

/// The keyring parses and every data key unwraps; the current key's age (STORE-058).
fn check_keyring(d: &mut Doctor, path: &str, wrapper: Option<KeyFileWrapper<OsRandom>>) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            d.add("keyring", Status::Warn, "none: run ti profile create");
            return;
        }
        Err(e) => {
            d.add("keyring", Status::Fail, e.to_string());
            return;
        }
    };
    let file = match KeyringFile::parse(&bytes) {
        Ok(f) => f,
        Err(e) => {
            d.add("keyring", Status::Fail, format!("{}: {e}", e.code()));
            return;
        }
    };
    let Some(wrapper) = wrapper else {
        d.add(
            "keyring",
            Status::Fail,
            format!(
                "{} keys, not unwrapped: the key file is unusable",
                file.entries.len()
            ),
        );
        return;
    };
    match block_on(Keyring::open(&file, &wrapper, OsRandom)) {
        Ok(keyring) => {
            d.add(
                "keyring",
                Status::Ok,
                format!(
                    "{} keys unwrap, current kid {}",
                    file.entries.len(),
                    keyring.current_kid()
                ),
            );
            let days = now().0.saturating_sub(keyring.current_created().0) / 86_400;
            if days > KEY_MAX_AGE_DAYS {
                d.add(
                    "key_age",
                    Status::Warn,
                    format!("the current key is {days} days old: ti profile rotate"),
                );
            } else {
                d.add(
                    "key_age",
                    Status::Ok,
                    format!("the current key is {days} days old"),
                );
            }
        }
        Err(e) => d.add(
            "keyring",
            Status::Fail,
            format!(
                "{}: {e}; the key file does not belong to this keyring",
                e.code()
            ),
        ),
    }
}

/// Format level against this tool's range, integrity, and records per namespace.
fn check_database(d: &mut Doctor, selected: &Selected, db: Db, label: &'static str, path: &str) {
    let (level_check, integrity_check) = match db {
        Db::State => ("state_level", "state_integrity"),
        Db::Cache => ("cache_level", "cache_integrity"),
    };
    // a cache that does not open is replaced on its next use; state never is
    let broken = match db {
        Db::State => Status::Fail,
        Db::Cache => Status::Warn,
    };
    if !Path::new(path).exists() {
        d.add(level_check, Status::Ok, "not created yet");
        return;
    }
    let backend = match AnyBackend::open(selected.kind, Path::new(path), db) {
        Ok(b) => b,
        Err(e) => {
            d.add(
                level_check,
                broken,
                format!("does not open: {}: {e}", e.code()),
            );
            return;
        }
    };
    let inspection = backend.inspect();
    let backend = Traced::from_env(backend);
    match inspection {
        Ok(i) => {
            d.add(
                level_check,
                Status::Ok,
                format!(
                    "level {}, needs a reader of level {}; this tool reads up to {MAX_LEVEL}",
                    i.level, i.min_compatible
                ),
            );
            match i.integrity.as_deref() {
                Some("ok") => d.add(integrity_check, Status::Ok, "quick_check ok"),
                Some(problem) => d.add(integrity_check, broken, problem.to_owned()),
                None => {}
            }
        }
        Err(e) => {
            d.add(level_check, broken, format!("{}: {e}", e.code()));
            return;
        }
    }
    let database = match db {
        Db::State => Database::State,
        Db::Cache => Database::Cache,
    };
    for spec in registry::ALL.iter().filter(|ns| ns.database == database) {
        match count(&backend, spec.name) {
            Ok((records, expired)) => d.namespaces.push(NamespaceCount {
                namespace: spec.name,
                database: label,
                records,
                expired,
            }),
            Err(e) => d.add(
                "records",
                broken,
                format!("{}: {}: {e}", spec.name, e.code()),
            ),
        }
    }
}

/// All records of a namespace, and how many of them are expired: every record is live at
/// time 0, so the difference to the count at the current time is the expired ones.
fn count(backend: &Traced<AnyBackend>, ns: &str) -> Result<(u64, u64), StoreError> {
    let ns = Namespace::new(ns)?;
    let pages = |at: Timestamp| -> Result<u64, StoreError> {
        let mut n = 0u64;
        let mut cursor = None;
        loop {
            let page = block_on(backend.query(&Query {
                ns: ns.clone(),
                filters: Vec::new(),
                from: None,
                to: None,
                limit: 1000,
                cursor,
                now: at,
            }))?;
            n += page.records.len() as u64;
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(n),
            }
        }
    };
    let all = pages(Timestamp(0))?;
    let live = pages(now())?;
    Ok((all, all.saturating_sub(live)))
}
