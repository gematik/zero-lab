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

//! `ti cache clear`: removes every record of the profile's cache (`cache.db`): trust
//! material, OCSP responses and Konnektor service directories. The profile's state, its
//! TSL state and comfort IDs, stays.

use serde::Serialize;
use ti_store::store::registry::{self, Database};
use ti_store::store::{Backend as _, Namespace, StoreError};
use ti_types::Timestamp;

use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit, StoreFile};
use crate::output::{Document, Line, Output, SCHEMA};
use crate::store::profile::Selected;

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The profile whose cache was cleared.
    profile: String,
    /// `cache.db`, or the cache's files tree.
    path: String,
    removed_records: u64,
}

/// Runs `ti cache clear`.
pub fn clear(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let path = selected.cache_path().to_owned();
    let store = selected.open_cache()?;
    let fail = |error: StoreError| CliError::Store {
        profile: selected.profile.name.clone(),
        file: StoreFile::CacheDb,
        path: path.clone(),
        error,
    };
    let mut removed = 0u64;
    for spec in registry::ALL
        .iter()
        .filter(|ns| ns.database == Database::Cache)
    {
        let ns = Namespace::new(spec.name).map_err(&fail)?;
        let mut cursor = None;
        loop {
            // every record of the cache expires, so all are live at time 0
            let (page, next) =
                block_on(store.query(spec, &[], 1000, cursor, Timestamp(0))).map_err(&fail)?;
            for record in &page {
                block_on(store.backend().delete(&ns, &record.name)).map_err(&fail)?;
                removed += 1;
            }
            match next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    let report = Report {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        path,
        removed_records: removed,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section("Cache");
        doc.field("profile", Line::text(&report.profile));
        doc.field("path", Line::code(&report.path));
        doc.field(
            "removed",
            if removed == 0 {
                Line::dim("nothing was cached")
            } else {
                Line::text(format!("{removed} records"))
            },
        );
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}
