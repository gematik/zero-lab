//! The JSON contract: every command's real output against the schema `ti schema`
//! publishes for it, offline, from a cache seeded with the production fixtures.

mod support;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use support::{assert_conforms, schema, violations};

const ROOTS_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";
const TSL_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml";

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn ti(cache: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ti"))
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
        let dir = std::env::temp_dir().join(format!("ti-{name}-{}", std::process::id()));
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

fn json_of(cache: &Path, name: &str, args: &[&str]) -> Output {
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    let out = ti(cache, &all);
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

    let error = ti(
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
}

#[test]
fn cache_clear_removes_only_the_downloads() {
    let cache = SeededCache::new("clear");
    std::fs::write(cache.0.join("keep.txt"), "not ours").unwrap();
    let sds = cache.0.join("ti-connector/v1/sds");
    std::fs::create_dir_all(&sds).unwrap();
    std::fs::write(sds.join("0123456789abcdef.body"), "<sds/>").unwrap();
    let out = ti(&cache.0, &["--format", "json", "cache", "clear"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["removed_files"], 5);
    assert!(!cache.0.join("ti-pki").exists());
    assert!(!cache.0.join("ti-connector").exists());
    assert!(cache.0.join("keep.txt").exists(), "other files stay");

    let again = ti(&cache.0, &["--format", "json", "cache", "clear"]);
    let again: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["removed_files"], 0);
}

#[test]
fn schemas_are_published_by_name() {
    let dir = std::env::temp_dir();
    let all = ti(&dir, &["schema"]);
    let all: Value = serde_json::from_slice(&all.stdout).unwrap();
    let commands = all["commands"].as_object().unwrap();
    assert_eq!(commands.len(), 33);
    assert_eq!(commands["pki verify"], schema("pki verify"));

    let one = ti(&dir, &["schema", "pki", "tsl", "show"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&one.stdout).unwrap(),
        schema("pki tsl show")
    );

    let unknown = ti(&dir, &["--format", "json", "schema", "pki", "nope"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert_conforms("error", &unknown.stderr);
}

#[test]
fn roots_and_tsl_need_a_concrete_environment() {
    let cache = SeededCache::new("auto");
    let out = ti(
        &cache.0,
        &["pki", "roots", "list", "--offline", "--env", "auto"],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn offline_tsl_without_a_cache_says_how_to_fix_it() {
    let dir = std::env::temp_dir().join(format!("ti-empty-{}", std::process::id()));
    let out = ti(&dir, &["pki", "tsl", "show", "--offline"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("without --offline"));
}

#[test]
fn the_agent_guide_is_the_embedded_file() {
    let out = ti(&std::env::temp_dir(), &["agent"]);
    let guide = std::fs::read_to_string(manifest("AGENTS.md")).unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        guide.replace("{bin}", ti_cli::BIN),
        "the guide is AGENTS.md with the executable's name filled in"
    );
}

#[test]
fn the_name_comes_from_one_place() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_ti"));
    assert_eq!(
        exe.file_stem().unwrap().to_str(),
        Some(ti_cli::BIN),
        "rename the [[bin]] target and ti_cli::BIN together"
    );
    let dir = std::env::temp_dir();
    let version: Value =
        serde_json::from_slice(&ti(&dir, &["--format", "json", "version"]).stdout).unwrap();
    assert_eq!(version["name"], ti_cli::BIN);
    let guide = String::from_utf8(ti(&dir, &["agent"]).stdout).unwrap();
    assert!(!guide.contains("{bin}"), "every placeholder is filled");
    assert!(guide.contains(&format!("{} --format json pki verify", ti_cli::BIN)));
    let help = String::from_utf8(ti(&dir, &["--help"]).stdout).unwrap();
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
