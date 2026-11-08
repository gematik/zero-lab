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

//! Konnektor access for the `connector` commands: which `.kon` file (resolved as the Go
//! `ti` resolves it, sharing its files), the transport, the service directory through
//! the cache; the client's watcher writes a diagnostic line per call
//! ([`crate::http::client`]).

use ti_client::connector::connect;
use ti_client::connector::store::{self, Source};
use ti_connector_client::Timeouts;

use crate::cli::{ConnectorArgs, GlobalArgs};
use crate::error::CliError;
use crate::output::Output;

/// A Konnektor ready for calls.
pub type Session = ti_client::connector::Session;

/// Where the configuration's name came from, as `-v` and the errors say it.
fn source_text(source: Source) -> &'static str {
    match source {
        Source::Explicit => "-c or TI_CONNECTOR_CONFIG",
        Source::Active => "the active selection",
        Source::Default => "the default name",
    }
}

/// Opens the selected Konnektor: reads its `.kon` file, sets up TLS from it, and loads
/// the service directory (through the cache unless `--no-cache`).
///
/// # Errors
///
/// [`CliError::ConnectorConfig`] or [`CliError::Connector`].
pub fn open(args: &ConnectorArgs, global: &GlobalArgs, out: &Output) -> Result<Session, CliError> {
    let (name, source) = store::selected(args.connector_config.as_deref());
    let path = store::resolve(&name).map_err(|e| match (source, e) {
        (Source::Active, ti_client::Error::ConnectorConfig(message)) => {
            CliError::ConnectorConfig(format!(
                "{message}; it is the active selection, change it with `{} connector use`",
                crate::BIN
            ))
        }
        (_, e) => e.into(),
    })?;
    out.verbose(
        1,
        format_args!(
            "connector {name} ({}): {}",
            source_text(source),
            path.display()
        ),
    );
    let dotkon = store::read(&path)?;
    if !dotkon.variables.is_empty() {
        out.verbose(
            1,
            format_args!(
                "expanded from the environment: {}",
                dotkon.variables.join(", ")
            ),
        );
    }
    let timeouts = Timeouts {
        short: args.connector_timeout,
        long: args.card_timeout,
    };
    out.verbose(
        1,
        format_args!(
            "timeouts: {} s per call, {} s with the card terminal",
            timeouts.short.as_secs(),
            timeouts.long.as_secs()
        ),
    );
    let transport = crate::http::client(&global.net, out.verbosity()).connector(&dotkon)?;
    let cache = if args.no_cache {
        None
    } else {
        Some(crate::profile::open_cache(global)?)
    };
    let (connector, meta) = connect(&dotkon, transport, timeouts, cache)?;
    if let Some(meta) = meta {
        out.verbose(1, format_args!("service directory from {:?}", meta.source));
    }
    Ok(Session {
        connector,
        dotkon,
        name,
        comfort_user_id: args.comfort_user_id.clone(),
        state_dir: crate::profile::Profile::resolve(global)?.state_dir,
    })
}
