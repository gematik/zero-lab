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

//! The JSON contract: every command's real output against the schema `ti schema`
//! publishes for it, offline, from a cache seeded with the production fixtures.

mod support;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};
use support::{assert_conforms, assert_old_store_untouched, schema, seed_old_store, violations};

const ROOTS_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";
const TSL_URL: &str = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml";
/// Where the list's detached signature is published (A_21182).
const TSL_SIG_URL: &str = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.sig";
const TSL_OCSP_URL: &str = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.ocsp";
/// The published PU set.
const PROD_SET: &str = "../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL";
/// The time it was captured at.
const CAPTURED_AT: &str = "2026-11-01T16:47:42Z";

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn ti(cache: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env("TI_PROFILE", "default")
        .env_remove("TI_STATE_DIR")
        .env("TI_CACHE_DIR", cache)
        .env("XDG_CACHE_HOME", cache.join("xdg-cache"))
        .env("XDG_STATE_HOME", cache.join("state"))
        .env("XDG_CONFIG_HOME", cache.join("config"))
        .output()
        .unwrap()
}

/// A cache directory holding the production roots.json and TSL fixtures as if just
/// downloaded, in the layout of `ti-cli/src/file_cache.rs` and ti-pki's cache keys.
struct SeededCache(PathBuf);

/// The content of a cache file: `u8 1 ‖ u32 length ‖ metadata JSON ‖ body`.
fn cache_payload(fetched_at: u64, body: &[u8]) -> Vec<u8> {
    let meta = serde_json::json!({
        "etag": "\"fixture\"", "last_modified": null,
        "fetched_at": fetched_at, "max_age_secs": null,
    })
    .to_string();
    let mut out = vec![1];
    out.extend_from_slice(&u32::try_from(meta.len()).unwrap().to_be_bytes());
    out.extend_from_slice(meta.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Writes cache files into the default profile's cache directory below `dir`, as another
/// process sharing the profile would: `v1/<hex SHA-256 of the key>`, the key being
/// `<prefix>/<id>`.
fn seed_cache(dir: &Path, records: &[(&str, String, Vec<u8>)]) {
    let entries = dir.join("profiles/default/v1");
    std::fs::create_dir_all(&entries).unwrap();
    for (prefix, id, payload) in records {
        let hash = Sha256::digest(format!("{prefix}/{id}").as_bytes())
            .iter()
            .fold(String::new(), |mut hex, b| {
                write!(hex, "{b:02x}").unwrap();
                hex
            });
        std::fs::write(entries.join(hash), payload).unwrap();
    }
}

/// The id of a download in the cache: the first 8 bytes of SHA-256 of its URL, as ti-pki
/// keys it.
fn url_id(url: &str) -> String {
    Sha256::digest(url.as_bytes())[..8]
        .iter()
        .fold(String::new(), |mut id, b| {
            write!(id, "{b:02x}").unwrap();
            id
        })
}

impl SeededCache {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ti-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let records: Vec<_> = [
            (
                "ti-pki/v1/roots",
                ROOTS_URL,
                manifest("../ti-pki/src/roots-prod.json"),
            ),
            (
                "ti-pki/v1/tsl",
                TSL_URL,
                manifest(&format!("{PROD_SET}.xml")),
            ),
            (
                "ti-pki/v1/tsl-sig",
                TSL_SIG_URL,
                manifest(&format!("{PROD_SET}.sig")),
            ),
        ]
        .into_iter()
        .map(|(ns, url, body)| {
            (
                ns,
                url_id(url),
                cache_payload(now, &std::fs::read(body).unwrap()),
            )
        })
        .collect();
        seed_cache(&dir, &records);
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
        &["pki", "profiles", "describe", "hci-aut"],
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
        show["counts"]["kept"], 71,
        "as pinned in ti-pki's load tests"
    );
    let under_roots: usize = show["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| root["cas"].as_array().unwrap().len())
        .sum();
    assert_eq!(
        under_roots, 71,
        "every kept CA sits under the root that signed it"
    );
    assert_eq!(show["rejected"].as_array().unwrap().len(), 5);

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
    assert_eq!(
        names,
        ["GEM.RCA2", "GEM.RCA6", "GEM.RCA7", "GEM.RCA9", "GEM.RCA10"]
    );

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

/// The trust bundle: what it reports, and that it refuses to overwrite without being told.
#[test]
fn trust_export_writes_a_bundle_a_consumer_loads() {
    let cache = SeededCache::new("trust-export");
    let c = &cache.0;
    let run = offline;
    let out = c.join("trust-bundle.json").display().to_string();
    let args = ["pki", "trust", "export", "-o", &out];
    let exported = json_of(c, "pki trust export", &run(&args));
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(exported["environment"], "prod");
    assert_eq!(exported["output"], out.as_str());
    let written = std::fs::read(&out).unwrap();
    assert_eq!(exported["bytes"], written.len());
    assert_eq!(exported["fits_config_map"], true);
    let bundle = ti_pki::load::Bundle::from_slice(&written).unwrap();
    bundle
        .check_anchor(&ti_pki::TrustConfig::preset_prod())
        .unwrap();
    let published = std::fs::read(manifest(&format!("{PROD_SET}.xml"))).unwrap();
    assert_eq!(bundle.material.tsl, published);
    assert!(bundle.material.detached.is_some());

    let again = ti(c, &run(&args));
    assert!(!again.status.success());
    let with_force = [&args[..], &["--force"]].concat();
    json_of(c, "pki trust export", &run(&with_force));
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
    assert!(!names.is_empty(), "{names:?}");
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
    assert_eq!(
        std::fs::read(c.join("tsl.sig")).unwrap(),
        std::fs::read(manifest(&format!("{PROD_SET}.sig"))).unwrap(),
        "the list comes with its signature (TSLDET-013)"
    );
    assert_eq!(
        exported["signature_file"],
        c.join("tsl.sig").to_string_lossy().as_ref()
    );
    let published = std::fs::read(manifest(&format!("{PROD_SET}.xml"))).unwrap();
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

/// A past instant may need an older list, so `--at` leaves the TSL state alone: a corrupt
/// file does not stop it and is not rewritten. Without `--at` the same file is an error, which
/// shows this is the file the check reads.
#[test]
fn at_another_time_a_corrupt_tsl_state_is_neither_read_nor_rewritten() {
    let cache = SeededCache::new("at-corrupt-state");
    let c = &cache.0;
    let file = c
        .join("state/telematik/ti/profiles/default/tsl")
        .join(format!("{}.json", url_id(TSL_URL)));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, b"{\"id\":").unwrap();

    let at = ti(c, &offline(&["pki", "roots", "list"]));
    assert_eq!(
        at.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&at.stderr)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"{\"id\":");

    let now = ti(c, &["pki", "roots", "list", "--offline"]);
    assert_eq!(
        now.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&now.stderr)
    );
    assert!(
        String::from_utf8_lossy(&now.stderr).contains(&file.display().to_string()),
        "{}",
        String::from_utf8_lossy(&now.stderr)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"{\"id\":");
}

/// TSLDET-023: an export for another time carries no signer status, whatever the cache
/// holds: the files beside the list are the ones it was verified with.
#[test]
fn tsldet_023_a_tsl_export_at_another_time_writes_no_signer_status() {
    let cache = SeededCache::new("tsl-export-at");
    let c = &cache.0;
    seed_cache(
        c,
        &[(
            "ti-pki/v1/tsl-ocsp",
            url_id(TSL_OCSP_URL),
            cache_payload(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                &std::fs::read(manifest(&format!("{PROD_SET}.ocsp"))).unwrap(),
            ),
        )],
    );
    let tsl = c.join("tsl.xml").to_string_lossy().into_owned();
    let exported = json_of(
        c,
        "pki tsl export",
        &offline(&["pki", "tsl", "export", "-o", &tsl]),
    );
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert!(exported["signer_status_file"].is_null(), "{exported}");
    assert!(!c.join("tsl.ocsp").exists());
    assert!(c.join("tsl.sig").exists());
}

/// The subsets of `tsl bundle`: repeated filters, `--issues`, `--cert`, `--with-roots`.
#[test]
fn tsl_bundle_subsets() {
    let cache = SeededCache::new("tsl-subsets");
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

    // A repeated filter matches any of its values.
    let both = json_of(
        c,
        "pki tsl bundle",
        &run(&[
            "pki",
            "tsl",
            "bundle",
            "--ca",
            "atos.smcb",
            "--ca",
            "atos.hba",
        ]),
    );
    let both: Value = serde_json::from_slice(&both.stdout).unwrap();
    let both: Vec<&str> = both["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["common_name"].as_str().unwrap())
        .collect();
    assert!(
        both.iter().any(|n| n.starts_with("ATOS.SMCB-CA")),
        "{both:?}"
    );
    assert!(
        both.iter().any(|n| n.starts_with("ATOS.HBA-CA")),
        "{both:?}"
    );
    assert!(both.len() > names.len());

    // --issues: the CAs the TSL lets issue a type; tsl show reports the types.
    let tls = json_of(
        c,
        "pki tsl bundle",
        &run(&["pki", "tsl", "bundle", "--issues", "TLS-S"]),
    );
    let tls: Value = serde_json::from_slice(&tls.stdout).unwrap();
    let tls = tls["certificates"].as_array().unwrap().len();
    let shown = json_of(
        c,
        "pki tsl show",
        &run(&["pki", "tsl", "show", "--issues", "TLS-S"]),
    );
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let shown: Vec<&Value> = shown["roots"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|root| root["cas"].as_array().unwrap())
        .collect();
    assert_eq!(shown.len(), tls);
    assert!(tls > 0);
    assert!(shown.iter().all(|ca| {
        ca["issuable_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str().unwrap().contains("TLS-S"))
    }));
    assert!(
        names
            .iter()
            .all(|smcb| shown.iter().all(|ca| ca["common_name"] != *smcb))
    );

    // --cert selects the CAs of a chain file; --with-roots adds the root they chain to.
    let first = cas["certificates"][0]["pem"].as_str().unwrap();
    let chain = c.join("chain.pem");
    std::fs::write(&chain, first).unwrap();
    let chain = chain.to_string_lossy().into_owned();
    let selected = json_of(
        c,
        "pki tsl bundle",
        &run(&["pki", "tsl", "bundle", "--cert", &chain, "--with-roots"]),
    );
    let selected: Value = serde_json::from_slice(&selected.stdout).unwrap();
    let selected: Vec<&str> = selected["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["common_name"].as_str().unwrap())
        .collect();
    assert_eq!(selected.len(), 2, "{selected:?}");
    assert_eq!(selected[0], names[0]);
    assert!(selected[1].starts_with("GEM.RCA"), "{selected:?}");
}

/// `--nist-only` narrows to what a client without brainpool can use, after the walk and
/// the TSL were verified with brainpool: every non-brainpool root (GEM.RCA9 and
/// GEM.RCA10 are reached only through brainpool cross certificates) and the TSL's
/// non-brainpool CAs.
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
    assert_eq!(
        names,
        ["GEM.RCA7", "GEM.RCA9", "GEM.RCA10", "GEM.RCA6", "GEM.RCA2"]
    );
    assert_eq!(roots["trust"]["nist_only"], true);
    assert!(roots["trust"]["intermediates"].as_u64().unwrap() > 0);
    assert!(
        roots["trust"]["tsl"].is_object(),
        "the TSL verified with brainpool"
    );

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

    let count = |extra: &[&str]| {
        let args = [&["pki", "tsl", "bundle"][..], extra].concat();
        let out = json_of(c, "pki tsl bundle", &offline(&args));
        let out: Value = serde_json::from_slice(&out.stdout).unwrap();
        out["certificates"].as_array().unwrap().len()
    };
    let (all, nist) = (count(&[]), count(&["--nist-only"]));
    assert!(0 < nist && nist < all, "{nist} of {all}");
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
fn cache_clear_removes_only_the_profiles_cache() {
    let cache = SeededCache::new("clear");
    std::fs::write(cache.0.join("keep.txt"), "not ours").unwrap();
    seed_cache(
        &cache.0,
        &[(
            "ti-connector/v1/sds",
            "0123456789abcdef".into(),
            cache_payload(1, b"<sds/>"),
        )],
    );
    let out = ti(&cache.0, &["--format", "json", "cache", "clear"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["removed_records"], 4);
    assert_eq!(report["profile"], "default");
    assert!(cache.0.join("keep.txt").exists(), "other files stay");

    let again = ti(&cache.0, &["--format", "json", "cache", "clear"]);
    let again: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["removed_records"], 0);
}

/// Writes `len` bytes to `path`, creating the directories above it.
fn put(path: &Path, len: usize) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, vec![b'x'; len]).unwrap();
}

fn state_base(c: &Path) -> PathBuf {
    c.join("state/telematik/ti")
}

fn json_value(c: &Path, name: &str, args: &[&str]) -> Value {
    let out = json_of(c, name, args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn profile_list_shows_the_slots_in_use() {
    let cache = SeededCache::new("profile-list");
    let c = &cache.0;
    put(&c.join("keep.txt"), 11);
    put(&state_base(c).join("tsl/abc.json"), 3);
    put(&state_base(c).join("profiles/work/hba-user/praxis/id"), 10);
    put(&c.join("profiles/work/v1/a"), 5);
    put(&c.join("profiles/home/v1/b"), 7);
    // not profiles: a name outside the rules, and a file
    put(&c.join("profiles/Bad Name/v1/c"), 100);
    put(&c.join("profiles/.hidden/v1/c"), 100);
    put(&c.join("profiles/afile"), 100);

    let listed = json_value(c, "profile list", &["profile", "list"]);
    let rows = listed["profiles"].as_array().unwrap();
    let row = |name: Option<&str>| {
        rows.iter()
            .find(|r| r["name"].as_str() == name)
            .unwrap_or_else(|| panic!("no row for {name:?}: {rows:?}"))
    };
    let names: Vec<Option<&str>> = rows.iter().map(|r| r["name"].as_str()).collect();
    assert_eq!(
        names,
        [None, Some("default"), Some("home"), Some("work")],
        "the unnamed location first, then the names in order"
    );
    let sizes = |r: &Value| (r["state_bytes"].as_u64(), r["cache_bytes"].as_u64());
    // The harness keeps the state base inside the cache base: 13 bytes of state are
    // files below the unnamed cache directory, the profiles' directories are not.
    assert_eq!(
        sizes(row(None)),
        (Some(3), Some(11 + 13)),
        "without profiles/"
    );
    assert_eq!(sizes(row(Some("work"))), (Some(10), Some(5)));
    assert_eq!(
        sizes(row(Some("home"))),
        (Some(0), Some(7)),
        "0 where a directory does not exist"
    );
    assert!(row(Some("default"))["cache_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn profile_delete_removes_state_and_cache() {
    let cache = SeededCache::new("profile-delete");
    let c = &cache.0;
    let (state, work_cache) = (state_base(c).join("profiles/work"), c.join("profiles/work"));
    put(&state.join("hba-user/praxis/id"), 10);
    put(&work_cache.join("v1/a"), 5);
    put(&state_base(c).join("profiles/only-state/x"), 1);
    put(&c.join("profiles/only-cache/v1/y"), 1);

    let refused = ti(c, &["profile", "delete", "work"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--yes"));
    assert!(state.exists() && work_cache.exists());

    let deleted = json_value(c, "profile delete", &["profile", "delete", "work", "--yes"]);
    assert_eq!(deleted["profile"], "work");
    let removed: Vec<&str> = deleted["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(
        removed,
        [state.to_str().unwrap(), work_cache.to_str().unwrap()]
    );
    assert!(!state.exists() && !work_cache.exists());
    assert!(c.join("profiles/default").exists(), "other profiles stay");

    for name in ["only-state", "only-cache"] {
        let one = json_value(c, "profile delete", &["profile", "delete", name, "--yes"]);
        assert_eq!(one["removed"].as_array().unwrap().len(), 1, "{name}");
    }
    let unknown = ti(c, &["profile", "delete", "nobody", "--yes"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("nobody"));
}

/// A directory of the cache base that cannot be removed is the cache's failure, not the
/// state's: the two have their own kinds and hints.
#[cfg(unix)]
#[test]
fn a_cache_directory_that_cannot_be_deleted_is_a_cache_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let cache = SeededCache::new("profile-delete-cache-fails");
    let c = &cache.0;
    put(&c.join("profiles/stuck/file"), 1);
    let parent = c.join("profiles/stuck");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out = ti(
        c,
        &["profile", "delete", "stuck", "--yes", "--format", "json"],
    );
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("cache_failed"), "{stderr}");
}

#[test]
fn profile_delete_refuses_a_path() {
    let cache = SeededCache::new("profile-delete-path");
    let c = &cache.0;
    put(&c.join("x/keep"), 1);
    put(&state_base(c).join("x/keep"), 1);
    for name in ["../x", "a/b", "."] {
        let out = ti(c, &["profile", "delete", "--yes", name]);
        assert_eq!(out.status.code(), Some(2), "{name}");
    }
    assert!(c.join("x/keep").exists() && state_base(c).join("x/keep").exists());
}

#[cfg(unix)]
#[test]
fn profile_delete_does_not_follow_a_symlink() {
    let cache = SeededCache::new("profile-delete-link");
    let c = &cache.0;
    put(&c.join("outside/precious"), 1);
    put(&state_base(c).join("outside/precious"), 1);
    std::fs::create_dir_all(c.join("profiles")).unwrap();
    std::fs::create_dir_all(state_base(c).join("profiles")).unwrap();
    std::os::unix::fs::symlink(c.join("outside"), c.join("profiles/linked")).unwrap();
    std::os::unix::fs::symlink(
        state_base(c).join("outside"),
        state_base(c).join("profiles/linked"),
    )
    .unwrap();

    json_value(
        c,
        "profile delete",
        &["profile", "delete", "linked", "--yes"],
    );
    assert!(std::fs::symlink_metadata(c.join("profiles/linked")).is_err());
    assert!(std::fs::symlink_metadata(state_base(c).join("profiles/linked")).is_err());
    assert!(c.join("outside/precious").exists());
    assert!(state_base(c).join("outside/precious").exists());
}

/// The trust commands read neither the state nor the cache of the sealed store. Seeded with
/// content no reader could parse, so a reader on any of the paths fails the command; the
/// comfort commands are `tests/connector.rs`'s.
#[test]
fn the_old_store_files_are_not_read() {
    let cache = SeededCache::new("old-store");
    let c = &cache.0;
    let empty = c.join("nothing-cached");
    let old = seed_old_store(&c.join("state"), &[c, &empty], &c.join("config"));

    // The list comes from the cache alone, so this fails if the cache is read elsewhere.
    let cached = ti(c, &offline(&["pki", "tsl", "show"]));
    // Without --at the TSL state is read and, with nothing cached, nothing depends on the
    // date the test runs at.
    let state = ti(
        c,
        &[
            "--cache-dir",
            empty.to_str().unwrap(),
            "--format",
            "json",
            "pki",
            "roots",
            "list",
            "--offline",
        ],
    );
    for out in [cached, state] {
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_old_store_untouched(&old);
}

#[test]
fn removed_commands_are_gone() {
    let c = std::env::temp_dir().join(format!("ti-removed-{}", std::process::id()));
    for args in [
        &["store", "doctor"][..],
        &["store", "ls"],
        &["profile", "create"],
        &["profile", "use", "work"],
        &["profile", "show"],
        &["profile", "rotate"],
        &["profile", "rewrap", "--kek-file", "/k"],
    ] {
        let out = ti(&c, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
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
    let tsl = manifest(&format!("{PROD_SET}.xml"));
    let sig = manifest(&format!("{PROD_SET}.sig"));
    let (tsl, sig) = (tsl.to_str().unwrap(), sig.to_str().unwrap());
    let args = |at: &'static str| ["pki", "tsl", "verify", tsl, sig, "--at", at];
    let verified = json_of(c, "pki tsl verify", &args(CAPTURED_AT));
    assert_eq!(verified.status.code(), Some(0));
    let verified: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["tier"], "prod");
    assert_eq!(verified["anchor"]["common_name"], "GEM.TSL-CA3");
    let expired = json_of(c, "pki tsl verify", &args("2028-06-01T00:00:00Z"));
    assert_eq!(expired.status.code(), Some(1));
    let expired: Value = serde_json::from_slice(&expired.stdout).unwrap();
    assert_eq!(expired["code"], "certificate_not_valid_time");
    assert_eq!(expired["code_number"], 1021);
    assert!(expired["signer"].is_null());
}

/// TSLDET-020: the supplied status replaces the network query, and the report says so.
#[test]
fn tsl_verify_reports_the_supplied_status() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-detached-{}", std::process::id()));
    let set = |suffix: &str| {
        manifest(&format!(
            "../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.{suffix}"
        ))
    };
    let (xml, sig, ocsp) = (set("xml"), set("sig"), set("ocsp"));
    let out = json_of(
        &dir,
        "pki tsl verify",
        &[
            "pki",
            "tsl",
            "verify",
            xml.to_str().unwrap(),
            sig.to_str().unwrap(),
            "--signer-status",
            ocsp.to_str().unwrap(),
            "--at",
            "2026-11-01T16:47:42Z",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["result"], "valid");
    assert_eq!(report["tier"], "nonprod");
    assert_eq!(report["signer_status"]["status"], "good");
    assert_eq!(report["signer_status"]["responder_url"], "supplied");
    assert_eq!(report["warnings"], serde_json::json!([]));
}

/// The loaders' detached files through the real profile store, offline, at and before
/// the capture time: the list verifies by its `.sig`, and a past `--at` does not use the
/// `.ocsp`, whose answer says nothing about that time. A mock store could not see this.
#[test]
fn tsldet_023_a_past_time_does_not_use_the_published_status() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-show-det-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let set = |suffix: &str| {
        std::fs::read(manifest(&format!(
            "../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}"
        )))
        .unwrap()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let origin = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL";
    let roots = std::fs::read(manifest("../ti-pki/src/roots-prod.json")).unwrap();
    seed_cache(
        &dir,
        &[
            (
                "ti-pki/v1/roots",
                url_id(ROOTS_URL),
                cache_payload(now, &roots),
            ),
            (
                "ti-pki/v1/tsl",
                url_id(TSL_URL),
                cache_payload(now, &set("xml")),
            ),
            (
                "ti-pki/v1/tsl-sig",
                url_id(&format!("{origin}.sig")),
                cache_payload(now, &set("sig")),
            ),
            (
                "ti-pki/v1/tsl-ocsp",
                url_id(&format!("{origin}.ocsp")),
                cache_payload(now, &set("ocsp")),
            ),
        ],
    );
    for at in ["2026-11-01T16:47:42Z", "2026-11-01T10:00:00Z"] {
        let out = json_of(
            &dir,
            "pki tsl show",
            &[
                "pki",
                "tsl",
                "show",
                "--env",
                "prod",
                "--offline",
                "--at",
                at,
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "{at}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            report["warnings"],
            serde_json::json!(["no_ocsp_check"]),
            "{at}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stdin can be read once: two inputs from it are a usage error, not an empty signature
/// reported as an invalid list.
#[test]
fn tsl_verify_takes_at_most_one_input_from_stdin() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-stdin-{}", std::process::id()));
    let sig = manifest(&format!("{PROD_SET}.sig"));
    for args in [
        vec!["pki", "tsl", "verify", "-", "-"],
        vec![
            "pki",
            "tsl",
            "verify",
            "-",
            sig.to_str().unwrap(),
            "--signer-status",
            "-",
        ],
    ] {
        assert_eq!(ti(&dir, &args).status.code(), Some(2), "{args:?}");
    }
}

/// The list and its signature are both required, in that order.
#[test]
fn tsl_verify_needs_the_signature() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-args-{}", std::process::id()));
    let xml = manifest(&format!("{PROD_SET}.xml"));
    let out = ti(&dir, &["pki", "tsl", "verify", xml.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}

/// TSLDET-005 through the CLI: a changed list fails on the detached signature.
#[test]
fn tsl_verify_rejects_a_tampered_list() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-tampered-{}", std::process::id()));
    let xml = manifest("../../spec/tsl-detached/testdata/derived/ref-tampered.xml");
    let sig = manifest("../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.sig");
    let out = json_of(
        &dir,
        "pki tsl verify",
        &[
            "pki",
            "tsl",
            "verify",
            xml.to_str().unwrap(),
            sig.to_str().unwrap(),
            "--at",
            "2026-11-01T16:47:42Z",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["code"], "detached_signature_error");
    assert_eq!(report["rule"], "TSLDET-005");
}

/// Offline: the warning instead of the signer's status; --previous decides the sequence.
#[test]
fn tsl_verify_offline_with_a_previous_list() {
    let dir = std::env::temp_dir().join(format!("ti-tsl-previous-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = |p: PathBuf| p.to_str().unwrap().to_owned();
    let list = path(manifest(&format!("{PROD_SET}.xml")));
    let sig = path(manifest(&format!("{PROD_SET}.sig")));
    let older = path(manifest(
        "../../spec/tsl-xmldsig/testdata/tsl/real/pu-10334.xml",
    ));
    // --previous only reads a list's identity: a later one is made from the published one.
    let later = dir.join("later.xml");
    let published = String::from_utf8(std::fs::read(&list).unwrap()).unwrap();
    std::fs::write(
        &later,
        published
            .replace("<TSLSequenceNumber>10337<", "<TSLSequenceNumber>10338<")
            .replacen("ID31033720261028000007Z", "ID31033820261127000007Z", 1),
    )
    .unwrap();
    let later = path(later);
    let verify = |extra: &[&str]| {
        let mut args = vec!["pki", "tsl", "verify", &list, &sig, "--offline"];
        args.extend_from_slice(extra);
        json_of(&dir, "pki tsl verify", &args)
    };
    let newer_out = verify(&["--previous", &older, "--at", CAPTURED_AT]);
    assert_eq!(newer_out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&newer_out.stdout).unwrap();
    assert_eq!(report["sequence"], "newer");
    assert_eq!(report["warnings"][0]["code"], "no_ocsp_check");
    assert_eq!(report["warnings"][0]["code_number"], 1039);
    assert!(report["signer_status"].is_null());

    let rollback = verify(&["--previous", &later, "--at", CAPTURED_AT]);
    assert_eq!(rollback.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(report["code"], "tsl_id_incorrect");
    assert_eq!(report["rule"], "TSLSIG-053");

    // Past its NextUpdate of 2026-11-27T00:00:07Z.
    let overdue = verify(&["--at", "2026-11-28T00:00:00Z", "--grace", "3"]);
    assert_eq!(overdue.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&overdue.stdout).unwrap();
    assert_eq!(report["warnings"][0]["code"], "validity_warning_1");

    let grace = ti(
        &dir,
        &["pki", "tsl", "verify", &list, &sig, "--grace", "31"],
    );
    assert_eq!(grace.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// TSLSIG-053: the state a run left is read by the next process, with no setup, and a
/// file that does not parse stops the run instead of dropping the rollback check.
#[test]
fn a_corrupt_tsl_state_stops_the_next_run_naming_the_file() {
    let cache = SeededCache::new("corrupt-tsl-state");
    let dir = cache.0.join("state/telematik/ti/profiles/default/tsl");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{}.json", url_id(TSL_URL)));
    std::fs::write(&file, b"{\"id\":").unwrap();

    let out = ti(
        &cache.0,
        &["--format", "json", "pki", "tsl", "show", "--offline"],
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "state_file_failed");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&file.display().to_string()),
        "{error}"
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"{\"id\":", "left as it is");
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
    assert_eq!(commands.len(), 51);
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
        .env("TI_PROFILE", "default")
        .env_remove("TI_STATE_DIR")
        .env("TI_CACHE_DIR", &cache.0)
        .env("XDG_STATE_HOME", cache.0.join("state"))
        .env("XDG_CONFIG_HOME", cache.0.join("config"))
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
    let errors = check(serde_json::json!({"a": 1, "b": "x"}));
    assert!(errors.is_empty(), "{errors:?}");
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
