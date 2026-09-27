//! The JSON Schema subset checker shared by the integration tests.

#![allow(dead_code, reason = "each test file uses a part")]

use std::path::PathBuf;

use serde_json::Value;

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
