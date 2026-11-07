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

//! Reading certificates from a file or stdin: PEM, DER or PKCS#12.

use std::io::Read;
use std::path::Path;

pub use ti_client::input::Loaded;

use crate::cli::P12PasswordArgs;
use crate::error::CliError;

/// The password of PKCS#12 input: `--p12-password`, else the first line of the file
/// `--p12-password-path` (or `TI_P12_PASSWORD_PATH`) names, else `00`.
pub fn p12_password(args: &P12PasswordArgs) -> Result<String, CliError> {
    if let Some(password) = &args.p12_password {
        return Ok(password.clone());
    }
    let Some(path) = &args.p12_password_path else {
        return Ok("00".to_owned());
    };
    let source = read(path)?;
    let text = String::from_utf8(source.bytes).map_err(|error| CliError::Read {
        source_name: source.name,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    })?;
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

/// The first line of a secret file (`--client-secret-path`, a token file): secrets are
/// read from files, never taken as values.
pub fn first_line(path: &std::path::Path) -> Result<String, CliError> {
    let source = read(path)?;
    let unreadable = |error: std::io::Error| CliError::Read {
        source_name: source.name.clone(),
        source: error,
    };
    let text = String::from_utf8(source.bytes.clone())
        .map_err(|error| unreadable(std::io::Error::new(std::io::ErrorKind::InvalidData, error)))?;
    let line = text.lines().next().unwrap_or_default().trim().to_owned();
    if line.is_empty() {
        return Err(unreadable(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty",
        )));
    }
    Ok(line)
}

/// The bytes of a FILE argument, with a name for messages.
pub struct Source {
    /// The file name, or `<stdin>`.
    pub name: String,
    /// The raw content.
    pub bytes: Vec<u8>,
}

/// Reads `path`, or stdin for `-`. Bytes, not text: DER is binary.
pub fn read(path: &Path) -> Result<Source, CliError> {
    if path == Path::new("-") {
        let name = "<stdin>".to_owned();
        let mut bytes = Vec::new();
        return match std::io::stdin().lock().read_to_end(&mut bytes) {
            Ok(_) => Ok(Source { name, bytes }),
            Err(source) => Err(CliError::Read {
                source_name: name,
                source,
            }),
        };
    }
    let name = path.display().to_string();
    std::fs::read(path)
        .map(|bytes| Source {
            name: name.clone(),
            bytes,
        })
        .map_err(|source| CliError::Read {
            source_name: name,
            source,
        })
}

/// The certificates in `source` ([`ti_client::input::certificates`]).
pub fn certificates(source: &Source, p12_password: &str) -> Result<Vec<Loaded>, CliError> {
    Ok(ti_client::input::certificates(
        &source.bytes,
        &source.name,
        p12_password,
    )?)
}
