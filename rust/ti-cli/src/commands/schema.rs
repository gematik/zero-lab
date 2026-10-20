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

//! `ti schema [COMMAND]`: the JSON contract of every command, as JSON Schema
//! (draft 2020-12). Hand-written next to the code and checked against real output by
//! the integration tests, so agents can rely on it.

use serde_json::{Map, Value};

use crate::error::{CliError, Exit};
use crate::output::{Output, SCHEMA};

/// Every command with JSON output, and the error document.
pub const SCHEMAS: [(&str, &str); 43] = [
    (
        "directory login",
        include_str!("../../schemas/directory-login.json"),
    ),
    (
        "idpd authenticate",
        include_str!("../../schemas/idpd-authenticate.json"),
    ),
    (
        "pki inspect",
        include_str!("../../schemas/pki-inspect.json"),
    ),
    ("pki verify", include_str!("../../schemas/pki-verify.json")),
    (
        "pki verify-signature",
        include_str!("../../schemas/pki-verify-signature.json"),
    ),
    (
        "identity inspect",
        include_str!("../../schemas/identity-inspect.json"),
    ),
    (
        "identity sign",
        include_str!("../../schemas/identity-sign.json"),
    ),
    (
        "pki profiles list",
        include_str!("../../schemas/pki-profiles-list.json"),
    ),
    (
        "pki profiles describe",
        include_str!("../../schemas/pki-profiles-describe.json"),
    ),
    (
        "pki roots list",
        include_str!("../../schemas/pki-roots-list.json"),
    ),
    (
        "pki roots bundle",
        include_str!("../../schemas/pki-roots-bundle.json"),
    ),
    (
        "pki tsl show",
        include_str!("../../schemas/pki-tsl-show.json"),
    ),
    (
        "pki tsl bundle",
        include_str!("../../schemas/pki-tsl-bundle.json"),
    ),
    (
        "pki tsl export",
        include_str!("../../schemas/pki-tsl-export.json"),
    ),
    (
        "pki tsl verify",
        include_str!("../../schemas/pki-tsl-verify.json"),
    ),
    (
        "cache clear",
        include_str!("../../schemas/cache-clear.json"),
    ),
    (
        "profile create",
        include_str!("../../schemas/profile-create.json"),
    ),
    (
        "pki pkcs12 convert",
        include_str!("../../schemas/pki-pkcs12-convert.json"),
    ),
    (
        "connector configs",
        include_str!("../../schemas/connector-configs.json"),
    ),
    (
        "connector use",
        include_str!("../../schemas/connector-use.json"),
    ),
    (
        "connector get info",
        include_str!("../../schemas/connector-get-info.json"),
    ),
    (
        "connector get services",
        include_str!("../../schemas/connector-get-services.json"),
    ),
    (
        "connector get cards",
        include_str!("../../schemas/connector-get-cards.json"),
    ),
    (
        "connector get certificates",
        include_str!("../../schemas/connector-get-certificates.json"),
    ),
    (
        "connector get status",
        include_str!("../../schemas/connector-get-status.json"),
    ),
    (
        "connector get identities",
        include_str!("../../schemas/connector-get-identities.json"),
    ),
    (
        "connector get expiration",
        include_str!("../../schemas/connector-get-expiration.json"),
    ),
    (
        "connector describe card",
        include_str!("../../schemas/connector-describe-card.json"),
    ),
    (
        "connector describe certificate",
        include_str!("../../schemas/pki-inspect.json"),
    ),
    (
        "connector verify pin",
        include_str!("../../schemas/connector-pin.json"),
    ),
    (
        "connector change pin",
        include_str!("../../schemas/connector-pin.json"),
    ),
    (
        "connector verify certificate",
        include_str!("../../schemas/connector-verify-certificate.json"),
    ),
    (
        "connector sign",
        include_str!("../../schemas/connector-sign.json"),
    ),
    (
        "connector verify signature",
        include_str!("../../schemas/connector-verify-signature.json"),
    ),
    (
        "connector encrypt",
        include_str!("../../schemas/connector-encrypt.json"),
    ),
    (
        "connector decrypt",
        include_str!("../../schemas/connector-decrypt.json"),
    ),
    (
        "connector comfort activate",
        include_str!("../../schemas/connector-comfort.json"),
    ),
    (
        "connector comfort status",
        include_str!("../../schemas/connector-comfort.json"),
    ),
    (
        "connector comfort deactivate",
        include_str!("../../schemas/connector-comfort.json"),
    ),
    (
        "connector export certificate",
        include_str!("../../schemas/connector-export-certificate.json"),
    ),
    ("probe", include_str!("../../schemas/probe.json")),
    ("version", include_str!("../../schemas/version.json")),
    ("error", include_str!("../../schemas/error.json")),
];

/// Runs `ti schema`: one schema, or all of them keyed by command. Always JSON.
pub fn run(command: &[String], out: &Output) -> Result<Exit, CliError> {
    let parse = |text: &str| -> Value {
        serde_json::from_str(text).expect("embedded schemas are valid JSON (tested)")
    };
    if command.is_empty() {
        let schemas: Map<String, Value> = SCHEMAS
            .iter()
            .map(|(name, text)| ((*name).to_owned(), parse(text)))
            .collect();
        out.json(&serde_json::json!({ "schema": SCHEMA, "commands": schemas }))?;
        return Ok(Exit::Ok);
    }
    let name = command.join(" ");
    let (_, text) = SCHEMAS
        .iter()
        .find(|(known, _)| *known == name)
        .ok_or(CliError::UnknownSchema(name))?;
    out.json(&parse(text))?;
    Ok(Exit::Ok)
}
