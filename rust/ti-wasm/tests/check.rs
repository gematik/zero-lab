//! `TrustContext` natively: certificates checked against the real TSLs of
//! `spec/tsl-xmldsig`, and the reports against `schemas/check.json`.

#[path = "../../ti-cli/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;

use serde_json::Value;
use support::assert_conforms;
use ti_wasm::api::{self, Context};

/// Within the validity of pu-10334 and tu-10713.
const NOW: &str = "2026-10-02T00:00:00Z";

fn manifest(path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn tsl(name: &str) -> Vec<u8> {
    manifest(&format!("../../spec/tsl-xmldsig/testdata/tsl/real/{name}"))
}

fn fixture(name: &str) -> Vec<u8> {
    manifest(&format!("../ti-pki/tests/fixtures/{name}"))
}

fn context(tsl_file: &str, env: &str) -> Context {
    Context::new(&tsl(tsl_file), env, NOW, None, 0).unwrap()
}

fn check(context: &Context, input: &[u8]) -> Value {
    let json = context.check(input, NOW).unwrap();
    assert_conforms("check", json.as_bytes());
    serde_json::from_str(&json).unwrap()
}

fn tree(report: &Value) -> Vec<(String, String, String)> {
    report["tree"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["name"].as_str().unwrap().to_owned(),
                n["role"].as_str().unwrap().to_owned(),
                n["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn codes(report: &Value) -> Vec<&str> {
    report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect()
}

/// A certificate of the production TSL, as PEM, by its common name.
fn listed_pem(name: &str) -> Vec<u8> {
    let view: Value =
        serde_json::from_str(&api::verify_tsl(&tsl("pu-10334.xml"), "prod", NOW, None, 0).unwrap())
            .unwrap();
    view["certificates"]
        .as_object()
        .unwrap()
        .values()
        .find(|c| {
            c["subject"]
                .as_str()
                .unwrap()
                .starts_with(&format!("CN={name},"))
        })
        .unwrap_or_else(|| panic!("{name} not in the TSL"))["pem"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec()
}

#[test]
fn smcb_on_reference() {
    let ctx = context("tu-10713.xml", "ref");
    for file in ["smcb-ee-test-only.pem", "admission-2.pem"] {
        let report = check(&ctx, &fixture(file));
        assert_eq!(report["result"], "valid", "{file}: {}", report["errors"]);
        assert_eq!(report["certificate_type"], "C.HCI.AUT");
        assert_eq!(report["profile"]["name"], "smb-aut");
        assert_eq!(report["revocation"], "not_checked");
        let nodes = tree(&report);
        assert_eq!(nodes[0].1, "C.HCI.AUT");
        assert_eq!(nodes[1].0, "GEM.SMCB-CA51 TEST-ONLY");
        assert_eq!(nodes[2].1, "root");
        assert!(nodes.iter().all(|n| n.2 == "ok"));
        // The CA is a service of the list, the end entity is not.
        assert!(report["tree"][1]["id"].is_string());
        assert!(report["tree"][0]["id"].is_null());
    }
}

#[test]
fn test_certificate_on_production() {
    let report = check(
        &context("pu-10334.xml", "prod"),
        &fixture("smcb-ee-test-only.pem"),
    );
    assert_eq!(report["result"], "invalid");
    assert_eq!(codes(&report), ["chain_incomplete"]);
    let nodes = tree(&report);
    assert_eq!(nodes.last().unwrap().1, "issuer");
    assert!(nodes.iter().all(|n| n.2 == "bad"));
}

#[test]
fn tsl_signer_on_production() {
    let report = check(
        &context("pu-10334.xml", "prod"),
        &fixture("tsl-signing-unit-6.pem"),
    );
    assert_eq!(report["result"], "valid", "{}", report["errors"]);
    assert_eq!(report["certificate_type"], "C.TSL.SIG");
    let names: Vec<String> = tree(&report).into_iter().map(|n| n.0).collect();
    assert_eq!(names, ["TSL Signing Unit 6", "GEM.TSL-CA3", "GEM.RCA4"]);
}

#[test]
fn expired_listed_certificate() {
    let report = check(
        &context("pu-10334.xml", "prod"),
        &listed_pem("MESIG.SMCB-OCSP2"),
    );
    assert_eq!(report["result"], "invalid");
    assert!(codes(&report).contains(&"expired"), "{}", report["errors"]);
}

#[test]
fn self_signed_ca_of_the_list() {
    let report = check(
        &context("pu-10334.xml", "prod"),
        &listed_pem("ATOS.EGK-CA14"),
    );
    assert_eq!(report["result"], "invalid");
    assert_eq!(tree(&report).last().unwrap().2, "bad");
}

#[test]
fn invalid_list_checks_nothing() {
    let ctx = context("pu-10334.xml", "test");
    let state: Value = serde_json::from_str(&ctx.tsl()).unwrap();
    assert_eq!(state["result"], "invalid");
    assert_eq!(state["error"]["code"], "certificate_not_valid_math");
    let report = check(&ctx, &fixture("smcb-ee-test-only.pem"));
    assert_eq!(report["result"], "invalid");
    assert_eq!(codes(&report), ["tsl_invalid"]);
}

#[test]
fn supplied_roots_fall_back_to_embedded() {
    let nonprod = manifest("../ti-pki/src/roots-nonprod.json");
    let ctx = Context::new(&tsl("pu-10334.xml"), "prod", NOW, Some(&nonprod), 0).unwrap();
    let state: Value = serde_json::from_str(&ctx.tsl()).unwrap();
    assert_eq!(state["result"], "valid");
    assert_eq!(state["roots_source"], "embedded");
    assert!(state["roots_warning"].is_string());
}

#[test]
fn der_and_pem_input_agree() {
    let ctx = context("tu-10713.xml", "ref");
    let pem = fixture("smcb-ee-test-only.pem");
    let der = ti_pki::parse_pem_certificates(&pem).unwrap()[0]
        .der()
        .to_vec();
    assert_eq!(check(&ctx, &pem)["tree"], check(&ctx, &der)["tree"]);
}

#[test]
fn caller_mistakes_are_errors() {
    let ctx = context("tu-10713.xml", "ref");
    assert!(ctx.check(b"not a certificate", NOW).is_err());
    assert!(ctx.check(&fixture("smcb-ee-test-only.pem"), "now").is_err());
    assert!(Context::new(&tsl("tu-10713.xml"), "moon", NOW, None, 0).is_err());
}
