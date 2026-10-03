//! `ti schema [COMMAND]`: the JSON contract of every command, as JSON Schema
//! (draft 2020-12). Hand-written next to the code and checked against real output by
//! the integration tests, so agents can rely on it.

use serde_json::{Map, Value};

use crate::error::{CliError, Exit};
use crate::output::{Output, SCHEMA};

/// Every command with JSON output, and the error document.
pub const SCHEMAS: [(&str, &str); 34] = [
    (
        "pki inspect",
        include_str!("../../schemas/pki-inspect.json"),
    ),
    ("pki verify", include_str!("../../schemas/pki-verify.json")),
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
        "pki tsl show",
        include_str!("../../schemas/pki-tsl-show.json"),
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
