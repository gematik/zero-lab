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
        .env("XDG_STATE_HOME", cache.join("state"))
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

    // The fixture TSL's validity, whenever the tests run.
    let at = ["--at", "2026-10-01T00:00:00Z"];
    let roots = json_of(
        c,
        "pki roots list",
        &[&["pki", "roots", "list", "--offline"][..], &at].concat(),
    );
    let roots: Value = serde_json::from_slice(&roots.stdout).unwrap();
    assert_eq!(roots["trust"]["source"], "cache");
    assert_eq!(roots["roots"].as_array().unwrap().len(), 10);
    assert_eq!(roots["roots"][0]["anchor"], true);

    let show = json_of(
        c,
        "pki tsl show",
        &[&["pki", "tsl", "show", "--offline"][..], &at].concat(),
    );
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
        &[&["pki", "tsl", "show", "--offline", "--rejected"][..], &at].concat(),
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

/// The identity commands, offline, on the TEST-ONLY SMC-B fixture.
#[test]
fn identity_commands_match_their_schemas() {
    let cache = SeededCache::new("identity-schema");
    let c = &cache.0;
    let identity = |name: &str| {
        manifest(&format!("tests/fixtures/identity/{name}"))
            .to_string_lossy()
            .into_owned()
    };
    json_of(
        c,
        "identity inspect",
        &["identity", "inspect", "--p12", &identity("aut.p12")],
    );
    let claims = c.join("claims.json");
    std::fs::write(&claims, br#"{"nonce":"n"}"#).unwrap();
    json_of(
        c,
        "identity sign",
        &[
            "identity",
            "sign",
            "--p12",
            &identity("aut.p12"),
            "--claims",
            &claims.to_string_lossy(),
        ],
    );
    let signature = json_of(
        c,
        "pki verify-signature",
        &[
            "pki",
            "verify-signature",
            "--cert",
            &identity("aut.pem"),
            "--data",
            &identity("data.bin"),
            "--signature",
            &identity("sig.der"),
        ],
    );
    assert_eq!(signature.status.code(), Some(0));
}

/// `args`, offline and in the fixture TSL's validity, whenever the tests run.
fn offline<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [args, &["--offline", "--at", "2026-10-01T00:00:00Z"]].concat()
}

/// The roots bundle, PEM and truststore: what it writes, and its report.
#[test]
fn roots_bundle_writes_what_it_reports() {
    let cache = SeededCache::new("roots-bundle");
    let c = &cache.0;
    let run = offline;

    let roots = json_of(c, "pki roots bundle", &run(&["pki", "roots", "bundle"]));
    let roots: Value = serde_json::from_slice(&roots.stdout).unwrap();
    assert_eq!(roots["format"], "pem");
    let certificates = roots["certificates"].as_array().unwrap();
    assert_eq!(certificates.len(), 10);
    assert!(certificates.iter().all(|c| c["pem"].is_string()));

    let pem = ti(c, &run(&["pki", "roots", "bundle"]));
    assert_eq!(pem.status.code(), Some(0));
    let pem = String::from_utf8(pem.stdout).unwrap();
    assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 10);

    let nist = json_of(
        c,
        "pki roots bundle",
        &run(&["pki", "roots", "bundle", "--nist-only"]),
    );
    let nist: Value = serde_json::from_slice(&nist.stdout).unwrap();
    let names: Vec<&str> = nist["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["common_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["GEM.RCA6", "GEM.RCA7"]);

    let p12 = c.join("roots.p12").to_string_lossy().into_owned();
    let written = json_of(
        c,
        "pki roots bundle",
        &run(&[
            "pki",
            "roots",
            "bundle",
            "--p12",
            "--p12-password",
            "changeit",
            "-o",
            &p12,
        ]),
    );
    let written: Value = serde_json::from_slice(&written.stdout).unwrap();
    assert_eq!(written["output"], p12.as_str());
    assert!(written["certificates"][0]["pem"].is_null());
    let store = ti_pkcs12::decode(&std::fs::read(&p12).unwrap(), "changeit").unwrap();
    assert_eq!(store.certificates.len(), 10);
    assert!(store.keys.is_empty());
    for bag in &store.certificates {
        assert_eq!(
            bag.trusted_key_usage,
            Some(ti_pkcs12::oids::ANY_EXTENDED_KEY_USAGE)
        );
        assert!(bag.friendly_name.as_deref().unwrap().starts_with("gem.rca"));
    }
    let again = ti(
        c,
        &run(&[
            "pki",
            "roots",
            "bundle",
            "--p12",
            "--p12-password",
            "x",
            "-o",
            &p12,
        ]),
    );
    assert_eq!(
        again.status.code(),
        Some(2),
        "an existing file without --force"
    );
    let no_password = ti(c, &run(&["pki", "roots", "bundle", "--p12"]));
    assert_eq!(
        no_password.status.code(),
        Some(2),
        "--p12 needs --p12-password"
    );
}

/// The TSL's CA bundle and the TSL export: what they write, and their reports.
#[test]
fn tsl_bundle_and_export_write_what_they_report() {
    let cache = SeededCache::new("tsl-bundle");
    let c = &cache.0;
    let run = offline;
    let cas = json_of(
        c,
        "pki tsl bundle",
        &run(&["pki", "tsl", "bundle", "--ca", "atos.smcb"]),
    );
    let cas: Value = serde_json::from_slice(&cas.stdout).unwrap();
    let names: Vec<&str> = cas["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["common_name"].as_str().unwrap())
        .collect();
    assert!(!names.is_empty());
    assert!(
        names.iter().all(|n| n.starts_with("ATOS.SMCB-CA")),
        "{names:?}"
    );
    assert!(cas["tsl_sequence_number"].is_u64());
    let none = ti(c, &run(&["pki", "tsl", "bundle", "--ca", "no such CA"]));
    assert_ne!(none.status.code(), Some(0));

    let tsl = c.join("tsl.xml").to_string_lossy().into_owned();
    let exported = json_of(
        c,
        "pki tsl export",
        &run(&["pki", "tsl", "export", "-o", &tsl]),
    );
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    let published =
        std::fs::read(manifest("../ti-pki/tests/fixtures/tsl/ECC-RSA_TSL.xml")).unwrap();
    assert_eq!(
        std::fs::read(&tsl).unwrap(),
        published,
        "the bytes as published"
    );
    assert_eq!(exported["bytes"], published.len());
    json_of(c, "pki tsl export", &run(&["pki", "tsl", "export"]));
    let raw = ti(c, &run(&["pki", "tsl", "export"]));
    assert_eq!(raw.stdout, published);
}

/// `--nist-only` verifies as a client without brainpool would: from GEM.RCA7 the walk
/// ends at the first brainpool root, and no TSL is loaded.
#[test]
fn nist_only_verifies_without_brainpool() {
    let cache = SeededCache::new("nist-only");
    let c = &cache.0;
    let fixture = |name: &str| {
        manifest(&format!("../ti-pki/tests/fixtures/{name}"))
            .to_string_lossy()
            .into_owned()
    };

    let roots = json_of(
        c,
        "pki roots list",
        &[
            "pki",
            "roots",
            "list",
            "--offline",
            "--nist-only",
            "--at",
            "2026-10-01T00:00:00Z",
        ],
    );
    let roots: Value = serde_json::from_slice(&roots.stdout).unwrap();
    let names: Vec<&str> = roots["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| root["common_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["GEM.RCA7", "GEM.RCA6"]);
    assert_eq!(roots["trust"]["nist_only"], true);
    assert_eq!(roots["trust"]["intermediates"], 0);
    assert!(roots["trust"]["tsl"].is_null());

    // The SMC-B CA under the brainpool GEM.RCA5 TEST-ONLY has no trusted issuer.
    let verify = json_of(
        c,
        "pki verify",
        &[
            "pki",
            "verify",
            "--offline",
            "--nist-only",
            &fixture("admission-1.pem"),
            "--issuer",
            &fixture("smcb-ca51-test-only.pem"),
            "--at",
            "2026-06-01T00:00:00Z",
        ],
    );
    assert_eq!(verify.status.code(), Some(1));
    let verify: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify["errors"][0]["code"], "chain_incomplete");
    assert_eq!(verify["trust"]["nist_only"], true);

    let tsl = ti(c, &["pki", "tsl", "show", "--nist-only"]);
    assert_eq!(
        tsl.status.code(),
        Some(2),
        "no such option on the TSL commands"
    );
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

/// The codes a verify report may carry are exactly ti-pki's.
#[test]
fn verify_codes_are_ti_pkis() {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest("schemas/pki-verify.json")).unwrap(),
    )
    .unwrap();
    let listed: Vec<&str> = schema["$defs"]["finding"]["properties"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let codes: Vec<&str> = ti_pki::ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(listed, codes);
}

/// Offline and without a cache: the file and the embedded TSL signer CA are all it needs.
#[test]
fn tsl_verify_matches_its_schema() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-verify-{}", std::process::id()));
    let c = &dir;
    let tsl = manifest("../ti-pki/tests/fixtures/tsl/ECC-RSA_TSL.xml");
    let tsl = tsl.to_str().unwrap();
    let verified = json_of(
        c,
        "pki tsl verify",
        &["pki", "tsl", "verify", tsl, "--at", "2026-10-01T00:00:00Z"],
    );
    assert_eq!(verified.status.code(), Some(0));
    let verified: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["tier"], "prod");
    assert_eq!(verified["anchor"]["common_name"], "GEM.TSL-CA3");
    let expired = json_of(
        c,
        "pki tsl verify",
        &["pki", "tsl", "verify", tsl, "--at", "2028-06-01T00:00:00Z"],
    );
    assert_eq!(expired.status.code(), Some(1));
    let expired: Value = serde_json::from_slice(&expired.stdout).unwrap();
    assert_eq!(expired["code"], "certificate_not_valid_time");
    assert_eq!(expired["code_number"], 1021);
    assert!(expired["signer"].is_null());
}

/// Offline: the warning instead of the signer's status; --previous decides the sequence.
#[test]
fn tsl_verify_offline_with_a_previous_list() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-previous-{}", std::process::id()));
    let real = |name: &str| {
        manifest(&format!("../../spec/tsl-xmldsig/testdata/tsl/real/{name}"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    let (older, newer) = (real("pu-10333.xml"), real("pu-10334.xml"));
    let at = "2026-10-01T00:00:00Z";
    let newer_out = json_of(
        &dir,
        "pki tsl verify",
        &[
            "pki",
            "tsl",
            "verify",
            &newer,
            "--previous",
            &older,
            "--offline",
            "--at",
            at,
        ],
    );
    assert_eq!(newer_out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&newer_out.stdout).unwrap();
    assert_eq!(report["sequence"], "newer");
    assert_eq!(report["warnings"][0]["code"], "no_ocsp_check");
    assert_eq!(report["warnings"][0]["code_number"], 1039);
    assert!(report["signer_status"].is_null());

    let rollback = json_of(
        &dir,
        "pki tsl verify",
        &[
            "pki",
            "tsl",
            "verify",
            &older,
            "--previous",
            &newer,
            "--offline",
            "--at",
            at,
        ],
    );
    assert_eq!(rollback.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(report["code"], "tsl_id_incorrect");
    assert_eq!(report["rule"], "TSLSIG-053");

    let overdue = json_of(
        &dir,
        "pki tsl verify",
        &[
            "pki",
            "tsl",
            "verify",
            &older,
            "--offline",
            "--at",
            "2026-10-15T00:00:00Z",
            "--grace",
            "3",
        ],
    );
    assert_eq!(overdue.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&overdue.stdout).unwrap();
    assert_eq!(report["warnings"][0]["code"], "validity_warning_1");

    let grace = ti(&dir, &["pki", "tsl", "verify", &older, "--grace", "31"]);
    assert_eq!(grace.status.code(), Some(2));
}

/// The codes a TSL verify report may carry are exactly ti-pki's.
#[test]
fn tsl_verify_codes_are_ti_pkis() {
    let listed = schema("pki tsl verify")["properties"]["code"]["enum"].clone();
    let mut codes: Vec<Value> = ti_pki::tsl_signature::TslCode::ALL
        .iter()
        .map(|c| Value::from(c.as_str()))
        .collect();
    codes.push(Value::Null);
    assert_eq!(listed, Value::Array(codes));
}

#[test]
fn schemas_are_published_by_name() {
    let dir = std::env::temp_dir();
    let all = ti(&dir, &["schema"]);
    let all: Value = serde_json::from_slice(&all.stdout).unwrap();
    let commands = all["commands"].as_object().unwrap();
    assert_eq!(commands.len(), 41);
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
    assert_conforms(
        "error",
        &ti(
            &cache.0,
            &["--format", "json", "pki", "tsl", "show", "--env", "auto"],
        )
        .stderr,
    );

    // From TI_ENV, auto is a default: production, where nothing can be detected.
    let from_variable = Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["--format", "json", "pki", "roots", "list", "--offline"])
        .args(["--at", "2026-10-01T00:00:00Z"])
        .env_remove("TI_FORMAT")
        .env("TI_ENV", "auto")
        .env("TI_CACHE_DIR", &cache.0)
        .env("XDG_STATE_HOME", cache.0.join("state"))
        .output()
        .unwrap();
    assert_eq!(from_variable.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&from_variable.stdout).unwrap();
    assert_eq!(report["environment"], "prod");
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
