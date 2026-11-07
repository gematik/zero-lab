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

//! The reports ti-report renders, as `ti` and ti-wasm hand them out: the formatting
//! helpers, a certificate as `ti pki inspect` shows it, the TSL view and a check. The JSON
//! is held to the published schemas (ti-cli's `pki-inspect`, ti-wasm's `tsl-view` and
//! `check`), which are the contract these reports keep. The inputs are fixed files and
//! fixed instants, so every result is deterministic.

#[path = "../../ti-cli/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;

use serde_json::{Value, json};
use ti_pki::tsl_signature::DetachedTsl;
use ti_pki::{Certificate, Env, Timestamp, TrustConfig, parse_pem_certificates};
use ti_report::{CheckContext, describe, fingerprint, hex, tsl_view, validity};

/// The capture time of the published sets in `spec/tsl-detached/testdata`.
const NOW: &str = "2026-11-01T16:47:42Z";

fn now() -> Timestamp {
    Timestamp::parse_rfc3339(NOW).unwrap()
}

fn read(path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn prod(suffix: &str) -> Vec<u8> {
    read(&format!(
        "../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}"
    ))
}

/// The TEST-ONLY SMC-B end-entity certificate of ti-pki's fixtures.
fn smcb() -> Certificate {
    parse_pem_certificates(&read("../ti-pki/tests/fixtures/smcb-ee-test-only.pem"))
        .unwrap()
        .remove(0)
}

fn conforms(schema_file: &str, value: &Value) {
    let schema: Value = serde_json::from_slice(&read(schema_file)).unwrap();
    let found = support::violations(value, &schema, &schema, "$");
    assert!(found.is_empty(), "{schema_file}:\n{}", found.join("\n"));
}

fn at(rfc3339: &str) -> Timestamp {
    Timestamp::parse_rfc3339(rfc3339).unwrap()
}

#[test]
fn hex_is_upper_case_pairs_joined_by_colons() {
    assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0A:FF:00");
    assert_eq!(hex(&[]), "");
}

#[test]
fn sha256_and_fingerprint_are_the_same_digest_in_two_notations() {
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(fingerprint(b""), empty);
    let cert = smcb();
    let sha256 = cert.fingerprint_sha256();
    assert_eq!(
        fingerprint(cert.der()),
        sha256.replace(':', "").to_lowercase()
    );
    assert_eq!(sha256.len(), 32 * 3 - 1);
}

/// Both bounds belong to the validity period.
#[test]
fn rfc_5280_4_1_2_5_validity_includes_both_bounds() {
    let cert = smcb();
    assert_eq!(validity(&cert, at("2023-11-09T22:59:59Z")), "not_yet_valid");
    assert_eq!(validity(&cert, at("2023-11-09T23:00:00Z")), "valid");
    assert_eq!(validity(&cert, at("2028-11-09T22:59:59Z")), "valid");
    assert_eq!(validity(&cert, at("2028-11-09T23:00:00Z")), "expired");
}

#[test]
fn describe_reads_what_the_certificate_says() {
    let cert = smcb();
    let info = describe(&cert, now());
    assert_eq!(
        info.subject,
        "CN=Arztpraxis Bernd Rosenstrauch TEST-ONLY,GN=Bernd,SN=Rosenstrauch,O=102310801 NOT-VALID,C=DE"
    );
    assert_eq!(info.serial, "02:B2:CB:70:12:37:28");
    assert_eq!(info.not_before, "2023-11-09T23:00:00Z");
    assert_eq!(info.not_after, "2028-11-09T22:59:59Z");
    assert_eq!(info.validity, "valid");
    assert_eq!(info.key_usage, ["digitalSignature"]);
    assert!(!info.ca);
    assert!(info.critical_extensions.iter().any(|e| e == "keyUsage"));
    assert!(
        info.critical_extensions
            .iter()
            .any(|e| e == "basicConstraints")
    );
    assert_eq!(info.sha256, cert.fingerprint_sha256());
    assert_eq!(info.pem, cert.to_pem());
}

#[test]
fn describe_judges_validity_at_the_instant_given() {
    let cert = smcb();
    assert_eq!(
        describe(&cert, at("2030-01-01T00:00:00Z")).validity,
        "expired"
    );
    assert_eq!(
        describe(&cert, at("2020-01-01T00:00:00Z")).validity,
        "not_yet_valid"
    );
}

/// The timestamps behind `not_before` and `not_after` are for views and never reach the
/// JSON; what does is exactly what ti-wasm's `describe_certificate` publishes, and what
/// `ti pki inspect` adds its PKCS#12 bag fields to.
#[test]
fn a_described_certificate_is_what_the_published_schemas_say() {
    let info = describe(&smcb(), now());
    let report = json!({
        "schema": ti_report::SCHEMA,
        "certificates": [info],
    });
    conforms("../ti-wasm/schemas/certificates.json", &report);

    let mut inspected = report["certificates"][0].clone();
    let fields = inspected.as_object_mut().unwrap();
    fields.insert("private_key".into(), json!(false));
    fields.insert("friendly_name".into(), Value::Null);
    fields.insert("local_key_id".into(), Value::Null);
    let inspect = json!({
        "schema": ti_report::SCHEMA,
        "source": "smcb-ee-test-only.pem",
        "certificates": [inspected],
        "pkcs12": null,
    });
    conforms("../ti-cli/schemas/pki-inspect.json", &inspect);
    let fields = report["certificates"][0].as_object().unwrap();
    assert!(!fields.contains_key("not_before_at"));
    assert!(!fields.contains_key("not_after_at"));
}

#[test]
fn the_view_of_the_published_production_tsl_is_valid_and_as_published() {
    let (xml, sig, ocsp) = (prod("xml"), prod("sig"), prod("ocsp"));
    let files = DetachedTsl {
        signature: &sig,
        signer_status: Some(&ocsp),
    };
    let view = tsl_view(
        &xml,
        files,
        Env::Prod,
        &TrustConfig::preset_prod(),
        None,
        now(),
    );
    assert_eq!(view.result, "valid");
    assert_eq!(view.environment, "prod");
    assert!(view.error.is_none());
    let json = serde_json::to_value(&view).unwrap();
    conforms("../ti-wasm/schemas/tsl-view.json", &json);
    // Certificates are filed under their fingerprint.
    for (key, cert) in &view.certificates {
        assert_eq!(key.len(), 64);
        assert_eq!(*key, cert.sha256.replace(':', "").to_lowercase());
    }
}

#[test]
fn the_view_of_a_tampered_list_is_the_verdict_only() {
    let mut xml = prod("xml");
    let at = xml.len() / 2;
    xml[at] ^= 0x01;
    let sig = prod("sig");
    let files = DetachedTsl {
        signature: &sig,
        signer_status: None,
    };
    let view = tsl_view(
        &xml,
        files,
        Env::Prod,
        &TrustConfig::preset_prod(),
        None,
        now(),
    );
    assert_eq!(view.result, "invalid");
    let error = view.error.as_ref().unwrap();
    assert_eq!(error.rule, "TSLDET-005");
    assert!(view.list.is_none());
    assert!(view.certificates.is_empty());
    conforms(
        "../ti-wasm/schemas/tsl-view.json",
        &serde_json::to_value(&view).unwrap(),
    );
}

fn context(xml: &[u8], roots: Option<&[u8]>) -> CheckContext {
    CheckContext::new(
        Env::Prod,
        TrustConfig::preset_prod(),
        roots,
        xml,
        &prod("sig"),
        now(),
    )
}

#[test]
fn a_check_against_the_production_tsl_reports_its_trust_material() {
    let context = context(&prod("xml"), None);
    let state = context.tsl();
    assert_eq!(state.result, "valid");
    assert_eq!(state.roots_source, "embedded");
    assert!(state.error.is_none());
    assert!(state.sequence_number.is_some());

    // A TEST-ONLY certificate has no place in production; the report says so and still
    // shows the certificate as `ti pki inspect` would.
    let cert = smcb();
    let report = context.check(std::slice::from_ref(&cert), now());
    assert_eq!(report.result, "invalid");
    assert_eq!(report.environment, "prod");
    assert_eq!(report.revocation, "not_checked");
    assert!(!report.errors.is_empty());
    assert_eq!(report.certificates.len(), 1);
    assert_eq!(report.certificates[0].sha256, cert.fingerprint_sha256());
    assert!(!report.tree.is_empty());
    conforms(
        "../ti-wasm/schemas/check.json",
        &serde_json::to_value(&report).unwrap(),
    );
}

#[test]
fn a_check_against_an_invalid_tsl_trusts_nothing() {
    let mut xml = prod("xml");
    let at = xml.len() / 2;
    xml[at] ^= 0x01;
    let context = context(&xml, None);
    assert_eq!(context.tsl().result, "invalid");
    assert_eq!(context.tsl().error.as_ref().unwrap().rule, "TSLDET-005");

    let report = context.check(&[smcb()], now());
    assert_eq!(report.result, "invalid");
    let codes: Vec<&str> = report.errors.iter().map(|e| e.code).collect();
    assert_eq!(codes, ["tsl_invalid"]);
    assert_eq!(report.tree.len(), 1);
    conforms(
        "../ti-wasm/schemas/check.json",
        &serde_json::to_value(&report).unwrap(),
    );
}

/// A roots.json that does not walk from the anchor falls back to the embedded roots, and
/// the report says why.
#[test]
fn unusable_supplied_roots_fall_back_to_the_embedded_ones_with_a_warning() {
    let context = context(&prod("xml"), Some(b"[]"));
    let state = context.tsl();
    assert_eq!(state.result, "valid");
    assert_eq!(state.roots_source, "embedded");
    assert!(
        state
            .roots_warning
            .as_deref()
            .is_some_and(|w| w.starts_with("supplied roots.json: "))
    );
}

#[test]
fn rejection_codes_are_stable() {
    use ti_pki::tsl::Rejection;
    use ti_report::tsl::rejection_code;
    assert_eq!(rejection_code(Rejection::NotCa), "not_ca");
    assert_eq!(rejection_code(Rejection::SelfSigned), "self_signed");
    assert_eq!(rejection_code(Rejection::UnknownIssuer), "unknown_issuer");
    assert_eq!(rejection_code(Rejection::BadSignature), "bad_signature");
}
