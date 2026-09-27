//! `ti schema [COMMAND]`: the JSON contract of every command, as JSON Schema
//! (draft 2020-12). Hand-written next to the code and checked against real output by
//! the integration tests, so agents can rely on it.

use serde_json::{Map, Value};

use crate::error::{CliError, Exit};
use crate::output::{Output, SCHEMA};

/// Every command with JSON output, and the error document.
pub const SCHEMAS: [(&str, &str); 11] = [
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
        "cache clear",
        include_str!("../../schemas/cache-clear.json"),
    ),
    (
        "pki pkcs12 convert",
        include_str!("../../schemas/pki-pkcs12-convert.json"),
    ),
    (
        "pki pkcs12 encode",
        include_str!("../../schemas/pki-pkcs12-encode.json"),
    ),
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
