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

//! `ti pki trust export`: the producer of a server's trust material. It writes one bundle file,
//! which a CronJob puts into a ConfigMap or a volume and an operator carries to an air-gapped
//! site. Nothing is written until a load of those very bytes has verified them, the way a
//! consumer will.

use std::io::Write as _;
use std::path::Path;

use serde::Serialize;
use ti_client::block_on;
use ti_pki::load::{Bundle, ReloadOutcome, ReloadPolicy, Reloader, StaticLoader};
use ti_pki::revocation::RevocationStatus;
use ti_pki::{Timestamp, TrustConfig};

use crate::cli::{GlobalArgs, TrustExportArgs};
use crate::error::{CliError, Exit};
use crate::output::document::when;
use crate::output::{Line, Output};
use crate::trust::Session;

/// What fits a ConfigMap: its limit of 1 MiB, less room for the object's own fields.
const CONFIG_MAP_ROOM: usize = 1_000_000;

/// The JSON document; `schema` is added on output.
#[derive(Serialize)]
struct Report {
    environment: &'static str,
    label: String,
    sequence_number: Option<u64>,
    next_update: Option<String>,
    /// What the set says of the TSL signer; absent if it holds no current status.
    signer_status: Option<&'static str>,
    /// When the set was fetched; what its age is measured from.
    fetched_at: String,
    bytes: usize,
    /// False: use a volume, a ConfigMap cannot hold it.
    fits_config_map: bool,
    output: String,
}

/// Runs `ti pki trust export`.
pub fn export(args: &TrustExportArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    if !args.force && args.output.exists() {
        return Err(CliError::OutputExists(args.output.display().to_string()));
    }
    let env = super::concrete(args.trust.env, global)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, args.trust.offline, out)?;
    let loaded = session.load(&config, env.tier(), args.trust.at)?;
    let material = session.verified_set(&config, &loaded, args.trust.at)?.set;
    let label = format!("{env} {}", material.fetched_at);
    let bytes = Bundle::new(&config, label.clone(), material).to_vec();

    // The time the set is checked at: now, or `--at`.
    let at = args.trust.at;
    let consumer = Bundle::from_slice(&bytes)
        .and_then(|bundle| StaticLoader::from_bundle(bundle, &config))
        .map_err(|e| CliError::TrustLoad(e.to_string()))?;
    let reloader = Reloader::new(
        config,
        env.tier(),
        consumer,
        move || at.unwrap_or_else(Timestamp::now),
        ReloadPolicy::default(),
    )
    .map_err(CliError::Trust)?;
    match block_on(reloader.tick()) {
        ReloadOutcome::Swapped { .. } => {}
        other => return Err(CliError::TrustLoad(format!("the set: {other:?}"))),
    }
    let status = reloader.handle().status();

    replace_file(&args.output, &bytes)?;
    let report = Report {
        environment: env.as_str(),
        label,
        sequence_number: status.tsl_state.as_ref().map(|s| s.sequence_number),
        next_update: status.tsl_next_update.map(|t| t.to_string()),
        signer_status: status.tsl_signer_status.map(RevocationStatus::as_str),
        fetched_at: status.fetched_at.map(|t| t.to_string()).unwrap_or_default(),
        bytes: bytes.len(),
        fits_config_map: bytes.len() <= CONFIG_MAP_ROOM,
        output: args.output.display().to_string(),
    };
    super::connector::emit(out, Exit::Ok, &report, |doc| {
        doc.paragraph(Line::strong("trust bundle").and_text(format!(" · {}", report.environment)));
        if let Some(fetched) = status.fetched_at {
            doc.field("fetched", when(fetched));
        }
        if let Some(next) = status.tsl_next_update {
            doc.field("next update", when(next));
        }
        doc.field("bytes", report.bytes.to_string());
        if !report.fits_config_map {
            doc.field("note", "too large for a ConfigMap, use a volume");
        }
        doc.field("to", Line::code(&report.output));
    })
}

/// Writes `path` whole or not at all, through a new file beside it: a consumer reading at any
/// moment, or a job that dies, leaves the previous set in place. On the same directory so the
/// rename stays atomic.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let failed = |error: std::io::Error| {
        CliError::Output(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        ))
    };
    let name = path.file_name().ok_or_else(|| {
        failed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a file name",
        ))
    })?;
    let mut temporary = name.to_owned();
    temporary.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(temporary);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ti-export-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_new_file_replaces_the_old_one_and_leaves_nothing_else() {
        let dir = scratch("replace");
        let path = dir.join("bundle");
        std::fs::write(&path, b"old").unwrap();
        replace_file(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn a_failure_leaves_the_old_file_and_no_temporary() {
        let dir = scratch("fail");
        let target = dir.join("is-a-directory");
        std::fs::create_dir(&target).unwrap();
        assert!(replace_file(&target, b"new").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(target.is_dir());
    }
}
