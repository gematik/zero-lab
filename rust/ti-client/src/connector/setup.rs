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

//! The `connector config test|new|edit|set|pin` operations: a `.kon` file judged without
//! its environment, a change refused where the rules of [`ti_connector_client::edit`]
//! say so, and the file tested against its Konnektor. Asking the user for what is
//! missing is the front end's.

use ti_connector_client::check::Report;
use ti_connector_client::config::ConfigView;
use ti_connector_client::{Dotkon, Timeouts, Transport, edit};
use ti_types::Timestamp;

use super::store::KonFile;
use super::{TestOptions, UreqTransport, agent_config, check_config};
use crate::error::Error;
use crate::net::Net;

/// `file` as it may be shown, without its secrets ([`ConfigView`]).
///
/// # Errors
///
/// [`Error::ConnectorConfig`] for a file that is not a valid configuration.
pub fn view(file: &KonFile) -> Result<ConfigView, Error> {
    let dotkon = Dotkon::parse(&file.json)
        .map_err(|e| Error::ConnectorConfig(format!("{}: {e}", file.path.display())))?;
    Ok(ConfigView::new(&dotkon, &file.json))
}

/// `json` parsed with every `${NAME}` set ([`edit::validate`]).
///
/// # Errors
///
/// [`Error::ConnectorConfig`] for a file that is not a valid configuration.
pub fn validate(json: &[u8]) -> Result<Dotkon, Error> {
    edit::validate(json).map_err(|e| Error::ConnectorConfig(e.to_string()))
}

/// Refuses what a change brings into a file ([`edit::refusals`]); `before` is the file
/// before it, `None` for a new one.
///
/// # Errors
///
/// [`Error::Refused`] naming each refusal.
pub fn refuse(before: Option<&Dotkon>, after: &Dotkon) -> Result<(), Error> {
    let refused = edit::refusals(before, after);
    if refused.is_empty() {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "{}; nothing saved",
            refused.join("; ")
        )))
    }
}

/// Tests the `.kon` file `json` against the Konnektor it names, step by step
/// ([`check_config`]), now. `mode` is its permission bits; `${NAME}` comes from the
/// process environment; the transport is `net`'s, with only an explicit proxy, through
/// `wrap`. Through a proxy TCP and TLS are not probed directly.
///
/// # Errors
///
/// [`Error::Setup`] for an unusable proxy.
pub fn test<T: Transport>(
    net: &Net,
    json: &[u8],
    mode: Option<u32>,
    timeouts: Timeouts,
    wrap: impl FnOnce(UreqTransport) -> T,
) -> Result<Report, Error> {
    let agent = agent_config(net)?;
    let options = TestOptions {
        connect_timeout: net.connect_timeout,
        timeouts,
        now: Timestamp::now(),
        through_proxy: net.explicit_proxy().is_some(),
    };
    Ok(check_config(
        json,
        mode,
        |name| std::env::var(name).ok(),
        |dotkon| UreqTransport::new(dotkon, agent).map(wrap),
        options,
    ))
}
