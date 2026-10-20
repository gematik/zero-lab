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

use std::fmt::Write as _;
use std::path::Path;

use base64ct::{Base64, Encoding as _};
use serde::Serialize;
use ti_store::store::levels::MAX_LEVEL;
use ti_store::store::registry::{self, Database, NamespaceSpec};
use ti_store::store::{
    Backend as _, KeyFileWrapper, Keyring, KeyringFile, Name, Namespace, OsRandom, Query,
    StoreError, StoredRecord, record_header,
};
use ti_types::Timestamp;

use crate::block::block_on;
use crate::cli::{GlobalArgs, StoreCommand};
use crate::error::{CliError, Exit, StoreFile};
use crate::output::{Document, Line, Output, SCHEMA, Tone};
use crate::store::profile::{ProfileStore, Selected, read_kek};
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
pub fn doctor(global: &GlobalArgs, json: bool, deep: bool, out: &Output) -> Result<Exit, CliError> {
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
    if deep {
        check_sealed_records(&mut d, &selected);
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

/// `--deep`: opens every live sealed record and counts those that do not, by result
/// code (STORE-123).
fn check_sealed_records(d: &mut Doctor, selected: &Selected) {
    use ti_store::store::Sealer as _;
    let path = selected.state_path();
    if !Path::new(path).exists() {
        d.add("records_open", Status::Ok, "no state yet");
        return;
    }
    let keyring = match selected.keyring() {
        Ok(Some(k)) => k,
        Ok(None) => {
            d.add("records_open", Status::Warn, "not checked: no keyring");
            return;
        }
        Err(e) => {
            d.add("records_open", Status::Fail, format!("not checked: {e}"));
            return;
        }
    };
    let backend = match AnyBackend::open(selected.kind, Path::new(path), Db::State) {
        Ok(b) => Traced::from_env(b),
        Err(e) => {
            d.add("records_open", Status::Fail, format!("{}: {e}", e.code()));
            return;
        }
    };
    let now = now();
    let (mut opened, mut failed) = (0u64, std::collections::BTreeMap::<&str, u64>::new());
    for spec in registry::ALL
        .iter()
        .filter(|ns| ns.kind == registry::Kind::Sealed && ns.database == Database::State)
    {
        let Ok(ns) = Namespace::new(spec.name) else {
            continue;
        };
        let mut cursor = None;
        loop {
            let page = match block_on(backend.query(&Query {
                ns: ns.clone(),
                filters: Vec::new(),
                from: None,
                to: None,
                limit: 1000,
                cursor,
                now,
            })) {
                Ok(p) => p,
                Err(e) => {
                    *failed.entry(e.code()).or_default() += 1;
                    break;
                }
            };
            for (name, record) in &page.records {
                match keyring.open(&ns, name, now, &record.value) {
                    Ok(_) => opened += 1,
                    Err(e) => *failed.entry(e.code()).or_default() += 1,
                }
            }
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    }
    if failed.is_empty() {
        d.add(
            "records_open",
            Status::Ok,
            format!("{opened} sealed records open"),
        );
    } else {
        let by_code: Vec<String> = failed.iter().map(|(c, n)| format!("{c} {n}")).collect();
        d.add(
            "records_open",
            Status::Fail,
            format!(
                "{} of {} sealed records do not open: {}; ti store rm removes one",
                failed.values().sum::<u64>(),
                opened + failed.values().sum::<u64>(),
                by_code.join(", ")
            ),
        );
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

/// A registered namespace, or `invalid_argument` with the list.
fn namespace(selected: &Selected, name: &str) -> Result<&'static NamespaceSpec, CliError> {
    registry::lookup(name).ok_or_else(|| {
        let known: Vec<&str> = registry::ALL.iter().map(|n| n.name).collect();
        CliError::Arguments(format!(
            "profile {}: no namespace {name:?}; the namespaces are {}",
            selected.profile.name,
            known.join(", ")
        ))
    })
}

fn database_of(spec: &NamespaceSpec) -> (Db, &'static str, StoreFile) {
    match spec.database {
        Database::State => (Db::State, "state", StoreFile::StateDb),
        Database::Cache => (Db::Cache, "cache", StoreFile::CacheDb),
    }
}

/// The store holding `spec`'s namespace: with the keyring when `sealed` work needs it,
/// else without, which is enough to read headers. None if its database does not exist.
fn store_for(
    selected: &Selected,
    spec: &NamespaceSpec,
    sealed: bool,
) -> Result<Option<ProfileStore>, CliError> {
    let (db, _, _) = database_of(spec);
    let path = match db {
        Db::State => selected.state_path(),
        Db::Cache => selected.cache_path(),
    };
    if !Path::new(path).exists() {
        return Ok(None);
    }
    Ok(Some(match db {
        Db::Cache => selected.open_cache()?,
        Db::State if sealed => selected.open_state()?,
        Db::State => selected.open_state_unsealed()?,
    }))
}

/// Every record of a namespace that is live at `at`, page by page.
fn records(
    store: &ProfileStore,
    ns: &Namespace,
    at: Timestamp,
) -> Result<Vec<(Name, StoredRecord)>, StoreError> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = block_on(store.backend().query(&Query {
            ns: ns.clone(),
            filters: Vec::new(),
            from: None,
            to: None,
            limit: 1000,
            cursor,
            now: at,
        }))?;
        out.extend(page.records);
        match page.cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
}

fn short(name: &Name) -> String {
    name.0[..8].iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn expiry_text(at: Option<Timestamp>) -> String {
    at.map_or_else(|| "never".into(), crate::output::document::when)
}

#[derive(Serialize)]
struct ListedRecord {
    namespace: &'static str,
    /// The first 8 bytes of the record's name, in hex; never the id.
    name: String,
    expires_at: Option<String>,
    payload_bytes: usize,
    /// The kid it is sealed under; none for a plain record.
    kid: Option<String>,
    /// The names of its indexed fields; never their values.
    fields: Vec<String>,
}

#[derive(Serialize)]
struct LsReport {
    schema: u32,
    profile: String,
    records: Vec<ListedRecord>,
}

/// `ti store ls [NS]` (STORE-124): what a record's header shows, never ids, tag values
/// or payloads; needs no keyring.
pub fn ls(global: &GlobalArgs, ns: Option<&str>, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let specs: Vec<&NamespaceSpec> = match ns {
        Some(name) => vec![namespace(&selected, name)?],
        None => registry::ALL.iter().collect(),
    };
    let now = now();
    let mut listed = Vec::new();
    for spec in specs {
        let (_, _, file) = database_of(spec);
        let Some(store) = store_for(&selected, spec, false)? else {
            continue;
        };
        let fail = |e: StoreError| selected.fail(file, spec.name, e);
        let ns = Namespace::new(spec.name).map_err(fail)?;
        for (name, record) in records(&store, &ns, now).map_err(fail)? {
            let header = record_header(&record.value).map_err(fail)?;
            listed.push(ListedRecord {
                namespace: spec.name,
                name: short(&name),
                expires_at: record.expires_at.map(crate::output::document::when),
                payload_bytes: header.payload_len,
                kid: header.kid.map(|k| k.to_string()),
                fields: record
                    .tags
                    .iter()
                    .map(|t| t.field.as_str().to_owned())
                    .collect(),
            });
        }
    }
    let report = LsReport {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        records: listed,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section(format!("Records of profile {}", report.profile));
    if report.records.is_empty() {
        doc.paragraph(Line::dim("no live records"));
    } else {
        doc.table(
            &["namespace", "name", "expires", "bytes", "kid", "fields"],
            report
                .records
                .iter()
                .map(|r| {
                    vec![
                        Line::code(r.namespace),
                        Line::code(&r.name),
                        Line::text(r.expires_at.clone().unwrap_or_else(|| "never".into())),
                        Line::text(r.payload_bytes.to_string()),
                        r.kid.as_ref().map_or(Line::dim("plain"), Line::text),
                        Line::text(r.fields.join(", ")),
                    ]
                })
                .collect(),
        );
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct ShowReport {
    schema: u32,
    profile: String,
    namespace: &'static str,
    name: String,
    expires_at: Option<String>,
    payload_bytes: usize,
    kid: Option<String>,
    fields: Vec<String>,
    /// Only with --reveal: the payload as text if it is UTF-8, else base64.
    payload: Option<String>,
    payload_encoding: Option<&'static str>,
}

/// `ti store show NS ID [--reveal]` (STORE-124): a record's metadata, and its payload
/// only on request.
pub fn show(
    global: &GlobalArgs,
    ns: &str,
    id: &str,
    reveal: bool,
    out: &Output,
) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let spec = namespace(&selected, ns)?;
    let (_, _, file) = database_of(spec);
    let fail = |e: StoreError| selected.fail(file, spec.name, e);
    let store = store_for(&selected, spec, true)?.ok_or_else(|| fail(StoreError::NotFound))?;
    let stored = block_on(store.get(spec, id.as_bytes(), now()))
        .map_err(|e| selected.fail(StoreFile::Record, &format!("{} {id}", spec.name), e))?;
    let ns_name = Namespace::new(spec.name).map_err(fail)?;
    let raw = block_on(store.backend().get(&ns_name, &stored.name, now())).map_err(fail)?;
    let (payload, payload_encoding) = if reveal {
        match std::str::from_utf8(&stored.payload) {
            Ok(text) => (Some(text.to_owned()), Some("utf-8")),
            Err(_) => (Some(Base64::encode_string(&stored.payload)), Some("base64")),
        }
    } else {
        (None, None)
    };
    let report = ShowReport {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        namespace: spec.name,
        name: short(&stored.name),
        expires_at: stored.expires_at.map(crate::output::document::when),
        payload_bytes: stored.payload.len(),
        kid: stored.kid.as_ref().map(ToString::to_string),
        fields: raw
            .tags
            .iter()
            .map(|t| t.field.as_str().to_owned())
            .collect(),
        payload,
        payload_encoding,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section(format!("{} {}", report.namespace, report.name));
    doc.field("expires", Line::text(expiry_text(stored.expires_at)));
    doc.field(
        "payload",
        Line::text(format!("{} bytes", report.payload_bytes)),
    );
    doc.field(
        "kid",
        report.kid.as_ref().map_or(Line::dim("plain"), Line::text),
    );
    if !report.fields.is_empty() {
        doc.field("fields", Line::text(report.fields.join(", ")));
    }
    match &report.payload {
        Some(p) => {
            doc.field(
                "content",
                Line::status(Tone::Warn, "revealed").and_text(format!(
                    " ({})",
                    report.payload_encoding.unwrap_or_default()
                )),
            );
            doc.paragraph(Line::code(p));
        }
        None => {
            doc.field("content", Line::dim("hidden: --reveal prints it"));
        }
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct RemoveReport {
    schema: u32,
    profile: String,
    namespace: &'static str,
    removed: u64,
}

fn emit_removed(out: &Output, report: &RemoveReport) -> Result<Exit, CliError> {
    if out.is_json() {
        out.json(report)?;
    } else {
        let mut doc = Document::default();
        doc.field(
            "removed",
            Line::text(format!(
                "{} from {}",
                plural(report.removed),
                report.namespace
            )),
        );
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

fn plural(n: u64) -> String {
    if n == 1 {
        "1 record".into()
    } else {
        format!("{n} records")
    }
}

/// `ti store rm NS ID` (STORE-124).
pub fn rm(global: &GlobalArgs, ns: &str, id: &str, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let spec = namespace(&selected, ns)?;
    let record =
        |e: StoreError| selected.fail(StoreFile::Record, &format!("{} {id}", spec.name), e);
    let removed = match store_for(&selected, spec, true)? {
        None => 0,
        Some(store) => {
            let existed = match block_on(store.get(spec, id.as_bytes(), now())) {
                // a record that does not open is still there, and removed by its id
                Ok(_)
                | Err(
                    StoreError::AuthFailed(_) | StoreError::UnknownKid | StoreError::Malformed(_),
                ) => true,
                Err(StoreError::NotFound) => false,
                Err(e) => return Err(record(e)),
            };
            block_on(store.delete(spec, id.as_bytes())).map_err(record)?;
            u64::from(existed)
        }
    };
    emit_removed(
        out,
        &RemoveReport {
            schema: SCHEMA,
            profile: selected.profile.name.clone(),
            namespace: spec.name,
            removed,
        },
    )
}

/// `ti store purge NS --yes` (STORE-124): every record of a namespace, live or expired.
pub fn purge(global: &GlobalArgs, ns: &str, yes: bool, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let spec = namespace(&selected, ns)?;
    if !yes {
        return Err(CliError::Arguments(format!(
            "purging {} removes every record of it from profile {}: pass --yes",
            spec.name, selected.profile.name
        )));
    }
    let (_, _, file) = database_of(spec);
    let fail = |e: StoreError| selected.fail(file, spec.name, e);
    let mut removed = 0u64;
    if let Some(store) = store_for(&selected, spec, false)? {
        let ns_name = Namespace::new(spec.name).map_err(fail)?;
        // every record that expires is live at time 0
        for (name, _) in records(&store, &ns_name, Timestamp(0)).map_err(fail)? {
            block_on(store.backend().delete(&ns_name, &name)).map_err(fail)?;
            removed += 1;
        }
    }
    emit_removed(
        out,
        &RemoveReport {
            schema: SCHEMA,
            profile: selected.profile.name.clone(),
            namespace: spec.name,
            removed,
        },
    )
}

#[derive(Serialize)]
struct CleanedDatabase {
    database: &'static str,
    path: String,
    removed: u64,
}

#[derive(Serialize)]
struct CleanupReport {
    schema: u32,
    profile: String,
    databases: Vec<CleanedDatabase>,
}

/// `ti store cleanup` (STORE-125): expired records out of both databases until none is
/// left, then the freed space back to the file system.
pub fn cleanup(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let now = now();
    let mut databases = Vec::new();
    for (db, label, file, path) in [
        (
            Db::State,
            "state",
            StoreFile::StateDb,
            selected.state_path(),
        ),
        (
            Db::Cache,
            "cache",
            StoreFile::CacheDb,
            selected.cache_path(),
        ),
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        let fail = |e: StoreError| selected.fail(file, path, e);
        let backend = AnyBackend::open(selected.kind, Path::new(path), db).map_err(fail)?;
        let backend = Traced::from_env(backend);
        let mut removed = 0u64;
        loop {
            let n = block_on(backend.cleanup(now, 1000)).map_err(fail)?;
            if n == 0 {
                break;
            }
            removed += n as u64;
        }
        backend.get_ref().vacuum().map_err(fail)?;
        backend.get_ref().set_last_cleanup(now).map_err(fail)?;
        databases.push(CleanedDatabase {
            database: label,
            path: path.to_owned(),
            removed,
        });
    }
    let report = CleanupReport {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        databases,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section(format!("Cleanup of profile {}", report.profile));
    if report.databases.is_empty() {
        doc.paragraph(Line::dim("no database yet"));
    }
    for d in &report.databases {
        doc.field(
            d.database,
            Line::text(format!("{} expired removed", plural(d.removed))),
        );
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct MigratedDatabase {
    database: &'static str,
    path: String,
    level: u16,
    min_compatible: u16,
    /// The levels it was or would be taken through; empty when nothing is to be done.
    steps: Vec<u16>,
    outcome: &'static str,
}

#[derive(Serialize)]
struct MigrateReport {
    schema: u32,
    profile: String,
    dry_run: bool,
    /// The highest level this tool reads and writes.
    max_level: u16,
    databases: Vec<MigratedDatabase>,
}

/// `ti store migrate [--dry-run]` (STORE-126): both databases to this tool's highest
/// level. Level 1 is the first, so there is no migration yet: the command reports where
/// each database stands, and refuses nothing a newer, compatible tool wrote.
pub fn migrate(global: &GlobalArgs, dry_run: bool, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let mut databases = Vec::new();
    for (db, label, file, path) in [
        (
            Db::State,
            "state",
            StoreFile::StateDb,
            selected.state_path(),
        ),
        (
            Db::Cache,
            "cache",
            StoreFile::CacheDb,
            selected.cache_path(),
        ),
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        let fail = |e: StoreError| selected.fail(file, path, e);
        let backend = AnyBackend::open(selected.kind, Path::new(path), db).map_err(fail)?;
        let i = backend.inspect().map_err(fail)?;
        let steps: Vec<u16> = (i.level + 1..=MAX_LEVEL).collect();
        let outcome = match (i.level.cmp(&MAX_LEVEL), dry_run) {
            (std::cmp::Ordering::Equal, _) => "up to date",
            (std::cmp::Ordering::Greater, _) => "newer than this tool, and compatible",
            (std::cmp::Ordering::Less, true) => "would migrate",
            (std::cmp::Ordering::Less, false) => "migrated",
        };
        databases.push(MigratedDatabase {
            database: label,
            path: path.to_owned(),
            level: i.level,
            min_compatible: i.min_compatible,
            steps,
            outcome,
        });
    }
    let report = MigrateReport {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        dry_run,
        max_level: MAX_LEVEL,
        databases,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section(format!(
        "Format levels of profile {} (this tool: up to {MAX_LEVEL})",
        report.profile
    ));
    if report.databases.is_empty() {
        doc.paragraph(Line::dim("no database yet"));
    }
    for d in &report.databases {
        doc.field(
            d.database,
            Line::text(format!(
                "level {}, needs {}: {}",
                d.level, d.min_compatible, d.outcome
            )),
        );
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// `ti store …`.
pub fn run(command: &StoreCommand, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    match command {
        StoreCommand::Doctor { json, deep } => doctor(global, *json, *deep, out),
        StoreCommand::Ls { namespace } => ls(global, namespace.as_deref(), out),
        StoreCommand::Show {
            namespace,
            id,
            reveal,
        } => show(global, namespace, id, *reveal, out),
        StoreCommand::Rm { namespace, id } => rm(global, namespace, id, out),
        StoreCommand::Purge { namespace, yes } => purge(global, namespace, *yes, out),
        StoreCommand::Cleanup => cleanup(global, out),
        StoreCommand::Migrate { dry_run } => migrate(global, *dry_run, out),
    }
}
