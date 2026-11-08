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

//! The IDP-Dienst's certificates checked against the TSL ([`ti_client::idp_trust`]),
//! as the command line asks for it.

use crate::cli::{Environment, GlobalArgs};
use crate::error::CliError;
use crate::output::Output;

/// How the IDP's certificates are judged.
pub type IdpTrust<'a> = ti_client::idp_trust::IdpTrust<'a, CliError>;

/// The check the command line asks for: `unverified`, or the TSL of `env` (`auto` detects
/// it from the certificate), its trust material loaded once it is needed.
pub fn idp_trust<'a>(
    unverified: bool,
    env: Option<Environment>,
    global: &'a GlobalArgs,
    out: &'a Output,
) -> IdpTrust<'a> {
    if unverified {
        out.verbose(
            1,
            "--idp-unverified: the IDP's certificates are used without a check against the TSL",
        );
        return IdpTrust::Unverified;
    }
    IdpTrust::tsl(env.and_then(Environment::concrete), move || {
        crate::trust::session(global, false, out)
    })
}
