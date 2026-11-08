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

//! `ti profile list|delete`: the profiles in use, each a directory below `profiles/` in
//! the state and the cache base ([`ti_client::profile`]).

use serde::Serialize;
use ti_client::profile::{self, Listed};

use crate::cli::{GlobalArgs, ProfileCommand};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA};
use crate::profile::{Profile, validate_name};

#[derive(Serialize)]
struct ListReport {
    schema: u32,
    profiles: Vec<Listed>,
}

/// `ti profile list`.
pub fn list(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let bases = Profile::bases(global)?;
    let report = ListReport {
        schema: SCHEMA,
        profiles: profile::list(&bases),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section("Profiles");
    let kib = |bytes: u64| Line::text(format!("{} KiB", bytes.div_ceil(1024)));
    doc.table(
        &["profile", "state", "cache"],
        report
            .profiles
            .iter()
            .map(|p| {
                let name = p.name.as_deref().map_or(Line::dim("(none)"), Line::text);
                vec![name, kib(p.state_bytes), kib(p.cache_bytes)]
            })
            .collect(),
    );
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct DeleteReport {
    schema: u32,
    profile: String,
    /// The directories removed, the state's first.
    removed: Vec<String>,
}

/// `ti profile delete NAME --yes`: `<state base>/profiles/NAME` and
/// `<cache base>/profiles/NAME`; the name is validated first, so that it cannot leave
/// `profiles/`.
pub fn delete(global: &GlobalArgs, name: &str, yes: bool, out: &Output) -> Result<Exit, CliError> {
    validate_name(name)?;
    if !yes {
        return Err(CliError::Arguments(format!(
            "deleting profile {name} removes its state and cache, with the TSL state and \
             comfort IDs in them: pass --yes"
        )));
    }
    let bases = Profile::bases(global)?;
    let removed: Vec<String> = profile::delete(&bases, name)?
        .iter()
        .map(|dir| dir.display().to_string())
        .collect();
    if removed.is_empty() {
        return Err(CliError::Arguments(format!(
            "no profile {name}: `{} profile list` shows the profiles",
            crate::BIN
        )));
    }
    let report = DeleteReport {
        schema: SCHEMA,
        profile: name.to_owned(),
        removed,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section(format!("Profile {} deleted", report.profile));
        for path in &report.removed {
            doc.field("removed", Line::code(path));
        }
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

/// `ti profile …`.
pub fn run(command: &ProfileCommand, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    match command {
        ProfileCommand::List => list(global, out),
        ProfileCommand::Delete { name, yes } => delete(global, name, *yes, out),
    }
}
