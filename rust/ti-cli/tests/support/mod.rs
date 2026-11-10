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

//! The JSON Schema subset checker shared by the integration tests.

#![allow(dead_code, reason = "each test file uses a part")]

use std::path::{Path, PathBuf};

use serde_json::Value;

/// What a file of the old store is seeded with: a reader would have to fail on it.
pub const OLD_STORE_CONTENT: &[u8] = b"not a database, a keyring or a key";

/// Writes the default profile's files of the sealed store, at the paths it kept them:
/// below `state` the keyring and state, below each of `caches` the cache, below `config`
/// the key file. The bases are what `$XDG_STATE_HOME`, `$XDG_CACHE_HOME` or `TI_CACHE_DIR`,
/// and `$XDG_CONFIG_HOME` name.
pub fn seed_old_store(state: &Path, caches: &[&Path], config: &Path) -> Vec<PathBuf> {
    let profile = |base: &Path, file: &str| base.join("profiles/default").join(file);
    let telematik = |base: &Path, file: &str| profile(&base.join("telematik"), file);
    let mut files = vec![
        telematik(state, "state.db"),
        telematik(state, "keyring.bin"),
        telematik(config, "store.kek"),
    ];
    for base in caches {
        files.push(telematik(base, "cache.db"));
        files.push(profile(base, "cache.db"));
    }
    for file in &files {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, OLD_STORE_CONTENT).unwrap();
    }
    files
}

pub fn assert_old_store_untouched(files: &[PathBuf]) {
    for file in files {
        assert_eq!(
            std::fs::read(file).unwrap(),
            OLD_STORE_CONTENT,
            "{}",
            file.display()
        );
    }
}

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// The published schema of command `name` (`schemas/<name with dashes>.json`).
pub fn schema(name: &str) -> Value {
    let file = manifest(&format!("schemas/{}.json", name.replace(' ', "-")));
    serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
}

/// Where `value` departs from `schema`: the subset of JSON Schema the published
/// schemas use (`$ref` into `$defs`, `oneOf`, `const`, `enum`, `type`, `properties`,
/// `required`, `additionalProperties`, `items`).
pub fn violations(value: &Value, schema: &Value, root: &Value, at: &str) -> Vec<String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/").unwrap();
        return violations(value, &root["$defs"][name], root, at);
    }
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        let fits = options
            .iter()
            .filter(|option| violations(value, option, root, at).is_empty())
            .count();
        return if fits == 1 {
            Vec::new()
        } else {
            vec![format!(
                "{at}: fits {fits} of the oneOf alternatives: {value}"
            )]
        };
    }
    let mut found = Vec::new();
    if let Some(expected) = schema.get("const")
        && value != expected
    {
        found.push(format!("{at}: {value} is not {expected}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        found.push(format!("{at}: {value} not in {allowed:?}"));
    }
    if let Some(types) = schema.get("type") {
        let types: Vec<&str> = match types {
            Value::String(t) => vec![t.as_str()],
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let actual = match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_u64() || n.is_i64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        if !types.contains(&actual) {
            found.push(format!("{at}: {actual} is not {types:?}"));
        }
    }
    if let Value::Object(fields) = value {
        let properties = schema.get("properties");
        for (key, field) in fields {
            let path = format!("{at}.{key}");
            match (
                properties.and_then(|p| p.get(key)),
                schema.get("additionalProperties"),
            ) {
                (Some(sub), _) => found.extend(violations(field, sub, root, &path)),
                (None, Some(Value::Bool(false))) => {
                    found.push(format!("{path}: not in the schema"));
                }
                (None, Some(sub @ Value::Object(_))) => {
                    found.extend(violations(field, sub, root, &path));
                }
                (None, _) => {}
            }
        }
        for key in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !fields.contains_key(key) {
                found.push(format!("{at}.{key}: required but missing"));
            }
        }
    }
    if let (Value::Array(items), Some(item_schema)) = (value, schema.get("items")) {
        for (i, item) in items.iter().enumerate() {
            found.extend(violations(item, item_schema, root, &format!("{at}[{i}]")));
        }
    }
    found
}

pub fn assert_conforms(name: &str, json: &[u8]) {
    let value: Value = serde_json::from_slice(json)
        .unwrap_or_else(|e| panic!("{name}: {e}: {}", String::from_utf8_lossy(json)));
    let schema = schema(name);
    let found = violations(&value, &schema, &schema, "$");
    assert!(found.is_empty(), "{name}:\n{}", found.join("\n"));
}

/// The schema of what `pki verify` wrote: a TLS server's verdict names its TLS profile,
/// the TI's report does not.
pub fn verify_schema(json: &[u8]) -> &'static str {
    let value: Value = serde_json::from_slice(json).unwrap_or_default();
    if value.get("tls_profile").is_some() {
        "pki verify tls-server"
    } else {
        "pki verify"
    }
}

/// [`assert_conforms`] with the schema of what `pki verify` wrote ([`verify_schema`]).
pub fn assert_verify_conforms(json: &[u8]) {
    assert_conforms(verify_schema(json), json);
}
