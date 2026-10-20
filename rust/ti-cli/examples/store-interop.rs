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

//! Drives a profile's store from Rust for spec/store's interoperability matrix
//! (`spec/store/interop/run.sh`), through ti's own backends and profile resolution; the
//! Go driver `go/sqlitestore/cmd/store-interop` takes the same arguments.
//!
//! ```text
//! store-interop put NS ID PAYLOAD [FIELD=VALUE ...]
//! store-interop get NS ID          # the payload; exit 3 if there is none
//! store-interop take NS ID         # the same, and the record is gone
//! store-interop query NS FIELD=VALUE ...   # the number of records
//! ```

use std::io::Write as _;
use std::process::ExitCode;

use futures_lite::future::block_on;
use ti_cli::store::now;
use ti_cli::store::profile::Selected;
use ti_store::store::StoreError;
use ti_store::store::registry::{self, Database};
use ti_types::Timestamp;

fn main() -> ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("store-interop: {code}: {message}");
            ExitCode::from(if code == "not_found" { 3 } else { 1 })
        }
    }
}

type Failure = (&'static str, String);

fn store_err(e: &StoreError) -> Failure {
    (e.code(), e.to_string())
}

fn run(args: &[String]) -> Result<(), Failure> {
    let usage = || {
        (
            "invalid_argument",
            "usage: store-interop put|get|take|query NS ...".to_owned(),
        )
    };
    let (op, ns) = match args {
        [op, ns, ..] => (op.as_str(), ns.as_str()),
        _ => return Err(usage()),
    };
    let spec = registry::lookup(ns).ok_or(("invalid_argument", format!("no namespace {ns:?}")))?;
    let selected = Selected::from_env().map_err(|e| ("backend_error", e.to_string()))?;
    let store = match spec.database {
        Database::State => selected.open_state(),
        Database::Cache => selected.open_cache(),
    }
    .map_err(|e| ("backend_error", e.to_string()))?;
    let now = now();
    match (op, &args[2..]) {
        ("put", [id, payload, meta @ ..]) => {
            let meta = metadata(meta)?;
            let fields: Vec<(&str, &[u8])> = meta
                .iter()
                .map(|(f, v)| (f.as_str(), v.as_bytes()))
                .collect();
            let expires = (spec.max_ttl > 0).then(|| Timestamp(now.0 + spec.max_ttl));
            block_on(store.put(
                spec,
                id.as_bytes(),
                payload.as_bytes(),
                &fields,
                expires,
                now,
            ))
            .map(drop)
            .map_err(|e| store_err(&e))
        }
        ("get" | "take", [id]) => {
            let stored = if op == "get" {
                block_on(store.get(spec, id.as_bytes(), now))
            } else {
                block_on(store.take(spec, id.as_bytes(), now))
            }
            .map_err(|e| store_err(&e))?;
            std::io::stdout()
                .write_all(&stored.payload)
                .map_err(|e| ("backend_error", e.to_string()))
        }
        ("query", meta) => {
            let meta = metadata(meta)?;
            let fields: Vec<(&str, &[u8])> = meta
                .iter()
                .map(|(f, v)| (f.as_str(), v.as_bytes()))
                .collect();
            let (mut n, mut cursor) = (0usize, None);
            loop {
                let (page, next) = block_on(store.query(spec, &fields, 1000, cursor, now))
                    .map_err(|e| store_err(&e))?;
                n += page.len();
                match next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            println!("{n}");
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn metadata(args: &[String]) -> Result<Vec<(String, String)>, Failure> {
    args.iter()
        .map(|a| {
            a.split_once('=')
                .map(|(f, v)| (f.to_owned(), v.to_owned()))
                .ok_or((
                    "invalid_argument",
                    format!("metadata {a:?} is not FIELD=VALUE"),
                ))
        })
        .collect()
}
