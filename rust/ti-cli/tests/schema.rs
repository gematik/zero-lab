//! The JSON contract: every command's real output against the schema `tir schema`
//! publishes for it, offline, from a cache seeded with the production fixtures.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOTS_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";
const TSL_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml";

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn tir(cache: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tir"))
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env("TI_CACHE_DIR", cache)
        .output()
        .unwrap()
}

/// A cache directory holding the production roots.json and TSL fixtures as if just
/// downloaded, in the layout of `ti-cli/src/cache.rs` and ti-pki's cache keys.
struct SeededCache(PathBuf);

impl SeededCache {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tir-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (kind, url, body) in [
            (
                "roots",
                ROOTS_URL,
                manifest("../ti-pki/src/roots-prod.json"),
            ),
            (
                "tsl",
                TSL_URL,
                manifest("../ti-pki/tests/fixtures/tsl/ECC-RSA_TSL.xml"),
            ),
        ] {
            let digest = Sha256::digest(url.as_bytes());
            let id = digest[..8].iter().fold(String::new(), |mut id, b| {
                write!(id, "{b:02x}").unwrap();
                id
            });
            let base = dir.join("ti-pki/v1").join(kind).join(id);
            std::fs::create_dir_all(base.parent().unwrap()).unwrap();
            std::fs::copy(body, base.with_extension("body")).unwrap();
            let meta = serde_json::json!({
                "etag": "\"fixture\"", "last_modified": null,
                "fetched_at": now, "max_age_secs": null,
            });
            std::fs::write(base.with_extension("json"), meta.to_string()).unwrap();
        }
        SeededCache(dir)
    }
}

impl Drop for SeededCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn schema(name: &str) -> Value {
    let file = manifest(&format!("schemas/{}.json", name.replace(' ', "-")));
    serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
}

/// Where `value` departs from `schema`: the subset of JSON Schema the published
/// schemas use (`$ref` into `$defs`, `oneOf`, `const`, `enum`, `type`, `properties`,
/// `required`, `additionalProperties`, `items`).
fn violations(value: &Value, schema: &Value, root: &Value, at: &str) -> Vec<String> {
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

fn assert_conforms(name: &str, json: &[u8]) {
    let value: Value = serde_json::from_slice(json)
        .unwrap_or_else(|e| panic!("{name}: {e}: {}", String::from_utf8_lossy(json)));
    let schema = schema(name);
    let found = violations(&value, &schema, &schema, "$");
    assert!(found.is_empty(), "{name}:\n{}", found.join("\n"));
}

fn json_of(cache: &Path, name: &str, args: &[&str]) -> Output {
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    let out = tir(cache, &all);
    assert_conforms(name, &out.stdout);
    out
}

#[test]
fn every_command_matches_its_schema() {
    let cache = SeededCache::new("schema");
    let fixture = |name: &str| {
        manifest(&format!("../ti-pki/tests/fixtures/{name}"))
            .to_string_lossy()
            .into_owned()
    };
    let (ee, ca) = (
        fixture("admission-1.pem"),
        fixture("smcb-ca51-test-only.pem"),
    );
    let c = &cache.0;

    json_of(c, "pki inspect", &["pki", "inspect", &ee]);
    json_of(c, "pki profiles list", &["pki", "profiles", "list"]);
    json_of(
        c,
        "pki profiles describe",
        &["pki", "profiles", "describe", "smb-aut"],
    );
    let valid = json_of(
        c,
        "pki verify",
        &[
            "pki",
            "verify",
            "--offline",
            &ee,
            "--issuer",
            &ca,
            "--at",
            "2026-06-01T00:00:00Z",
        ],
    );
    assert_eq!(valid.status.code(), Some(0));
    let invalid = json_of(
        c,
        "pki verify",
        &["pki", "verify", "--offline", "--env", "ref", &ee],
    );
    assert_eq!(invalid.status.code(), Some(1));

    let roots = json_of(c, "pki roots list", &["pki", "roots", "list", "--offline"]);
    let roots: Value = serde_json::from_slice(&roots.stdout).unwrap();
    assert_eq!(roots["trust"]["source"], "cache");
    assert_eq!(roots["roots"].as_array().unwrap().len(), 10);
    assert_eq!(roots["roots"][0]["anchor"], true);

    let show = json_of(c, "pki tsl show", &["pki", "tsl", "show", "--offline"]);
    let show: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(
        show["counts"]["kept"], 84,
        "as pinned in ti-pki's tsl tests"
    );
    let under_roots: usize = show["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| root["cas"].as_array().unwrap().len())
        .sum();
    assert_eq!(
        under_roots, 84,
        "every kept CA sits under the root that signed it"
    );
    assert_eq!(show["rejected"].as_array().unwrap().len(), 6);

    let rejected = json_of(
        c,
        "pki tsl show",
        &["pki", "tsl", "show", "--offline", "--rejected"],
    );
    let rejected: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["roots"].as_array().unwrap().len(), 0);
    assert_eq!(rejected["filtered"], true);
    assert!(
        rejected["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .all(|ca| !ca["rejection"].is_null())
    );

    let error = tir(
        c,
        &["--format", "json", "pki", "inspect", "/nonexistent.pem"],
    );
    assert_eq!(error.status.code(), Some(4));
    assert_conforms("error", &error.stderr);

    json_of(c, "cache clear", &["cache", "clear"]);
    json_of(c, "version", &["version"]);
}

#[test]
fn pkcs12_commands_match_their_schemas() {
    let cache = SeededCache::new("pkcs12");
    let c = &cache.0;
    let (p12, password) = (
        manifest("../ti-pkcs12/tests/fixtures/legacy/cgm.p12"),
        std::fs::read_to_string(manifest(
            "../ti-pkcs12/tests/fixtures/legacy/cgm-password.txt",
        ))
        .unwrap(),
    );
    let p12 = p12.to_str().unwrap();
    let password = password.trim();
    json_of(
        c,
        "pki inspect",
        &["pki", "inspect", p12, "--p12-password", password],
    );
    let converted = cache.0.join("converted.p12");
    json_of(
        c,
        "pki pkcs12 convert",
        &[
            "pki",
            "pkcs12",
            "convert",
            p12,
            converted.to_str().unwrap(),
            "--p12-password",
            password,
        ],
    );
    json_of(
        c,
        "pki pkcs12 encode",
        &["pki", "pkcs12", "encode", p12, "--p12-password", password],
    );
}

#[test]
fn cache_clear_removes_only_the_downloads() {
    let cache = SeededCache::new("clear");
    std::fs::write(cache.0.join("keep.txt"), "not ours").unwrap();
    let out = tir(&cache.0, &["--format", "json", "cache", "clear"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["removed_files"], 4);
    assert!(!cache.0.join("ti-pki").exists());
    assert!(cache.0.join("keep.txt").exists(), "other files stay");

    let again = tir(&cache.0, &["--format", "json", "cache", "clear"]);
    let again: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["removed_files"], 0);
}

#[test]
fn schemas_are_published_by_name() {
    let dir = std::env::temp_dir();
    let all = tir(&dir, &["schema"]);
    let all: Value = serde_json::from_slice(&all.stdout).unwrap();
    let commands = all["commands"].as_object().unwrap();
    assert_eq!(commands.len(), 11);
    assert_eq!(commands["pki verify"], schema("pki verify"));

    let one = tir(&dir, &["schema", "pki", "tsl", "show"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&one.stdout).unwrap(),
        schema("pki tsl show")
    );

    let unknown = tir(&dir, &["--format", "json", "schema", "pki", "nope"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert_conforms("error", &unknown.stderr);
}

#[test]
fn roots_and_tsl_need_a_concrete_environment() {
    let cache = SeededCache::new("auto");
    let out = tir(
        &cache.0,
        &["pki", "roots", "list", "--offline", "--env", "auto"],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn offline_tsl_without_a_cache_says_how_to_fix_it() {
    let dir = std::env::temp_dir().join(format!("tir-empty-{}", std::process::id()));
    let out = tir(&dir, &["pki", "tsl", "show", "--offline"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("without --offline"));
}

#[test]
fn the_agent_guide_is_the_embedded_file() {
    let out = tir(&std::env::temp_dir(), &["agent"]);
    let guide = std::fs::read_to_string(manifest("AGENTS.md")).unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        guide.replace("{bin}", ti_cli::BIN),
        "the guide is AGENTS.md with the executable's name filled in"
    );
}

#[test]
fn the_name_comes_from_one_place() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_tir"));
    assert_eq!(
        exe.file_stem().unwrap().to_str(),
        Some(ti_cli::BIN),
        "rename the [[bin]] target and ti_cli::BIN together"
    );
    let dir = std::env::temp_dir();
    let version: Value =
        serde_json::from_slice(&tir(&dir, &["--format", "json", "version"]).stdout).unwrap();
    assert_eq!(version["name"], ti_cli::BIN);
    let guide = String::from_utf8(tir(&dir, &["agent"]).stdout).unwrap();
    assert!(!guide.contains("{bin}"), "every placeholder is filled");
    assert!(guide.contains(&format!("{} --format json pki verify", ti_cli::BIN)));
    let help = String::from_utf8(tir(&dir, &["--help"]).stdout).unwrap();
    assert!(!help.contains("{bin}"), "{help}");
    assert!(help.contains(&format!("Usage: {} ", ti_cli::BIN)), "{help}");
}

#[test]
fn the_checker_catches_departures() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"enum": ["x"]}},
        "required": ["a", "b"],
        "additionalProperties": false,
    });
    let check = |value: Value| violations(&value, &schema, &schema, "$");
    assert!(check(serde_json::json!({"a": 1, "b": "x"})).is_empty());
    assert_eq!(
        check(serde_json::json!({"a": "1", "b": "x"})).len(),
        1,
        "type"
    );
    assert_eq!(
        check(serde_json::json!({"a": 1, "b": "y"})).len(),
        1,
        "enum"
    );
    assert_eq!(check(serde_json::json!({"a": 1})).len(), 1, "required");
    assert_eq!(
        check(serde_json::json!({"a": 1, "b": "x", "c": 0})).len(),
        1,
        "extra field"
    );
}
