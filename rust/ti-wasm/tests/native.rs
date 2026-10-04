//! The exports on the real TSLs of `spec/tsl-xmldsig`, natively: verdicts per
//! environment, grace period, supplied roots, and the JSON against the published schemas.

#[path = "../../ti-cli/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;

use serde_json::Value;
use support::assert_conforms;
use ti_wasm::api;

/// Within the validity of pu-10334 and tu-10713.
const NOW: &str = "2026-10-02T00:00:00Z";
const DAY: u32 = 24 * 3600;

fn real(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/tsl-xmldsig/testdata/tsl/real")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn view(tsl: &str, env: &str, now: &str, roots: Option<&[u8]>, grace: u32) -> Value {
    let json = api::verify_tsl(&real(tsl), env, now, roots, grace).unwrap();
    assert_conforms("tsl-view", json.as_bytes());
    serde_json::from_str(&json).unwrap()
}

fn warnings(view: &Value) -> Vec<&str> {
    view["signature"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect()
}

fn root_names(view: &Value) -> Vec<&str> {
    view["roots"]["trusted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["common_name"].as_str().unwrap())
        .collect()
}

#[test]
fn production_list_for_production() {
    let v = view("pu-10334.xml", "prod", NOW, None, 0);
    assert_eq!(v["result"], "valid", "{}", v["error"]);
    assert_eq!(v["tier"], "prod");
    assert_eq!(v["list"]["sequence_number"], 10334);
    assert_eq!(v["list"]["scheme"]["operator_name"], "gematik GmbH");
    assert_eq!(warnings(&v), ["no_ocsp_check"]);
    assert!(root_names(&v).iter().all(|cn| !cn.contains("TEST-ONLY")));
    assert!(v["counts"]["cas_kept"].as_u64().unwrap() > 0);

    let certificates = v["certificates"].as_object().unwrap();
    let signer = v["signature"]["signer"].as_str().unwrap();
    assert_eq!(certificates[signer]["certificate_type"], "C.TSL.SIG");
    // Every fingerprint the document names resolves.
    for service in v["providers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["services"].as_array().unwrap())
    {
        for fp in service["chain"]["path"].as_array().into_iter().flatten() {
            assert!(certificates.contains_key(fp.as_str().unwrap()));
        }
    }
}

#[test]
fn every_kept_ca_and_ocsp_responder_chains_to_a_root() {
    let v = view("pu-10334.xml", "prod", NOW, None, 0);
    let roots: Vec<&str> = v["roots"]["trusted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["fingerprint"].as_str().unwrap())
        .collect();
    let services: Vec<&Value> = v["providers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["services"].as_array().unwrap())
        .collect();
    let trusted_cas = services
        .iter()
        .filter(|s| s["kind"] == "ca" && s["chain"]["trusted"] == true)
        .count();
    assert_eq!(
        trusted_cas as u64,
        v["counts"]["cas_kept"].as_u64().unwrap()
    );
    let ocsp: Vec<&&Value> = services
        .iter()
        .filter(|s| s["kind"] == "ocsp" && s["chain"]["trusted"] == true)
        .collect();
    assert!(!ocsp.is_empty());
    for service in services.iter().filter(|s| s["chain"]["trusted"] == true) {
        let path = service["chain"]["path"].as_array().unwrap();
        assert!(roots.contains(&path.last().unwrap().as_str().unwrap()));
    }
}

#[test]
fn test_list_for_test_and_reference() {
    for env in ["test", "ref"] {
        let v = view("tu-10713.xml", env, NOW, None, 0);
        assert_eq!(v["result"], "valid", "{env}: {}", v["error"]);
        assert_eq!(v["tier"], "nonprod");
        assert_eq!(
            v["list"]["scheme"]["operator_name"],
            "TEST-ONLY gematik GmbH"
        );
    }
}

#[test]
fn lists_of_the_other_tier_are_invalid() {
    for (tsl, env) in [("tu-10713.xml", "prod"), ("pu-10334.xml", "test")] {
        let v = view(tsl, env, NOW, None, 0);
        assert_eq!(v["result"], "invalid");
        assert_eq!(
            v["error"]["code"], "certificate_not_valid_math",
            "{tsl} {env}"
        );
        assert!(v["providers"].as_array().unwrap().is_empty());
        assert!(v["certificates"].as_object().unwrap().is_empty());
    }
}

#[test]
fn a_flipped_byte_breaks_the_signature() {
    let mut xml = real("pu-10334.xml");
    let at = xml
        .windows(b"gematik GmbH".len())
        .position(|w| w == b"gematik GmbH")
        .unwrap();
    xml[at] = b'G';
    let json = api::verify_tsl(&xml, "prod", NOW, None, 0).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["error"]["code"], "xml_signature_error");
}

#[test]
fn grace_period_past_next_update() {
    // pu-10333's NextUpdate is 2026-10-13T23:00:08Z.
    let after = "2026-10-14T00:00:00Z";
    let v = view("pu-10333.xml", "prod", after, None, 0);
    assert_eq!(v["error"]["code"], "validity_warning_2");
    let v = view("pu-10333.xml", "prod", after, None, 7 * DAY);
    assert_eq!(v["result"], "valid");
    assert_eq!(v["list"]["overdue"], true);
    assert!(warnings(&v).contains(&"validity_warning_1"));
}

#[test]
fn supplied_roots_cannot_add_test_roots_to_production() {
    let nonprod = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-nonprod.json"),
    )
    .unwrap();
    let v = view("pu-10334.xml", "prod", NOW, Some(&nonprod), 0);
    assert_eq!(v["result"], "valid");
    assert_eq!(v["roots"]["source"], "embedded");
    assert!(v["roots"]["warning"].is_string());
    assert!(root_names(&v).iter().all(|cn| !cn.contains("TEST-ONLY")));

    let prod = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-prod.json"),
    )
    .unwrap();
    let v = view("pu-10334.xml", "prod", NOW, Some(&prod), 0);
    assert_eq!(v["roots"]["source"], "supplied");
}

#[test]
fn caller_mistakes_are_errors() {
    let xml = real("pu-10334.xml");
    assert!(api::verify_tsl(&xml, "moon", NOW, None, 0).is_err());
    assert!(api::verify_tsl(&xml, "prod", "yesterday", None, 0).is_err());
    assert!(api::verify_tsl(&xml, "prod", NOW, None, 31 * DAY).is_err());
    assert!(api::describe_certificate(b"not a certificate", NOW).is_err());
    assert!(api::trust_urls("moon").is_err());
}

#[test]
fn describes_the_signer_certificate() {
    let v = view("pu-10334.xml", "prod", NOW, None, 0);
    let signer = v["signature"]["signer"].as_str().unwrap();
    let pem = v["certificates"][signer]["pem"].as_str().unwrap();
    let json = api::describe_certificate(pem.as_bytes(), NOW).unwrap();
    assert_conforms("certificates", json.as_bytes());
    let described: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(described["certificates"][0], v["certificates"][signer]);
}

#[test]
fn urls_and_version() {
    let urls: Value = serde_json::from_str(&api::trust_urls("ref").unwrap()).unwrap();
    assert!(urls["tsl_url"].as_str().unwrap().contains("ref"));
    let version: Value = serde_json::from_str(&api::version()).unwrap();
    assert_eq!(version["schema"], 1);
}
