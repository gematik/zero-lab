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

//! `ti agent`: the usage guide for scripts and AI agents, compiled in so it matches
//! the binary and works offline.

use std::io::Write;

use crate::error::{CliError, Exit};

const GUIDE: &str = include_str!("../../AGENTS.md");

/// Prints the guide, `{bin}` replaced by the executable's name; Markdown whatever
/// `--format` says.
pub fn run() -> Result<Exit, CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(GUIDE.replace("{bin}", crate::BIN).as_bytes())?;
    out.flush()?;
    Ok(Exit::Ok)
}
