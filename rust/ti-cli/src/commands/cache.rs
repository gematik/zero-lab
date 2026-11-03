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

//! `ti cache clear`: removes every entry of the profile's download cache: trust
//! material, OCSP responses and Konnektor service directories. The profile's state, its
//! TSL state and comfort IDs, stays.

use serde::Serialize;

use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::file_cache;
use crate::output::{Document, Line, Output, SCHEMA};
use crate::profile::Profile;

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The profile whose cache was cleared; none without one.
    profile: Option<String>,
    /// The profile's cache directory.
    path: String,
    removed_records: u64,
}

/// Runs `ti cache clear`.
pub fn clear(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let profile = Profile::resolve(global)?;
    let path = profile.cache_dir.display().to_string();
    let removed = file_cache::clear(&profile.cache_dir).map_err(|e| {
        CliError::Output(std::io::Error::new(e.kind(), format!("cache {path}: {e}")))
    })?;
    let report = Report {
        schema: SCHEMA,
        profile: profile.name,
        path,
        removed_records: removed,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section("Cache");
        if let Some(name) = &report.profile {
            doc.field("profile", Line::text(name));
        }
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
