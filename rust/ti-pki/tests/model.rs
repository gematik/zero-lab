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

//! The projections of `model`: a certificate as `ti pki inspect` shows it, the TSL view and
//! the offline check. With the `serde` feature their JSON is held to the published schemas
//! (ti-cli's `pki-inspect`, ti-wasm's `certificates`, `tsl-view` and `check`), the contract
//! the front ends keep. The inputs are fixed files and fixed instants, so every result is
//! deterministic.

#[cfg(feature = "serde")]
#[path = "../../ti-cli/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;

use ti_pki::model::{self, rejection_code};
use ti_pki::tsl::Rejection;
use ti_pki::{Certificate, Timestamp, parse_pem_certificates};

/// The capture time of the published sets in `spec/tsl-detached/testdata`.
const NOW: &str = "2026-11-01T16:47:42Z";

fn now() -> Timestamp {
    Timestamp::parse_rfc3339(NOW).unwrap()
}

fn read(path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The TEST-ONLY SMC-B end-entity certificate of the fixtures.
fn smcb() -> Certificate {
    parse_pem_certificates(&read("tests/fixtures/smcb-ee-test-only.pem"))
        .unwrap()
        .remove(0)
}

fn at(rfc3339: &str) -> Timestamp {
    Timestamp::parse_rfc3339(rfc3339).unwrap()
}

/// Both bounds belong to the validity period.
#[test]
fn rfc_5280_4_1_2_5_validity_includes_both_bounds() {
    let cert = smcb();
    assert_eq!(
        model::validity(&cert, at("2023-11-09T22:59:59Z")),
        "not_yet_valid"
    );
    assert_eq!(model::validity(&cert, at("2023-11-09T23:00:00Z")), "valid");
    assert_eq!(model::validity(&cert, at("2028-11-09T22:59:59Z")), "valid");
    assert_eq!(
        model::validity(&cert, at("2028-11-09T23:00:00Z")),
        "expired"
    );
}

#[test]
fn describe_reads_what_the_certificate_says() {
    let cert = smcb();
    let info = model::Certificate::new(&cert, now());
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
        model::Certificate::new(&cert, at("2030-01-01T00:00:00Z")).validity,
        "expired"
    );
    assert_eq!(
        model::Certificate::new(&cert, at("2020-01-01T00:00:00Z")).validity,
        "not_yet_valid"
    );
}

#[test]
fn rejection_codes_are_stable() {
    assert_eq!(rejection_code(Rejection::NotCa), "not_ca");
    assert_eq!(rejection_code(Rejection::SelfSigned), "self_signed");
    assert_eq!(rejection_code(Rejection::UnknownIssuer), "unknown_issuer");
    assert_eq!(rejection_code(Rejection::BadSignature), "bad_signature");
}

#[cfg(feature = "serde")]
fn conforms(schema_file: &str, value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_slice(&read(schema_file)).unwrap();
    let found = support::violations(value, &schema, &schema, "$");
    assert!(found.is_empty(), "{schema_file}:\n{}", found.join("\n"));
}

/// The timestamps behind `not_before` and `not_after` are for views and never reach the
/// JSON; what does is exactly what ti-wasm's `describe_certificate` publishes, and what
/// `ti pki inspect` adds its PKCS#12 bag fields to.
#[cfg(feature = "serde")]
#[test]
fn a_described_certificate_is_what_the_published_schemas_say() {
    use serde_json::{Value, json};

    let info = model::Certificate::new(&smcb(), now());
    let report = json!({
        "schema": model::SCHEMA,
        "certificates": [info],
    });
    conforms("../ti-wasm/schemas/certificates.json", &report);

    let mut inspected = report["certificates"][0].clone();
    let fields = inspected.as_object_mut().unwrap();
    fields.insert("private_key".into(), json!(false));
    fields.insert("friendly_name".into(), Value::Null);
    fields.insert("local_key_id".into(), Value::Null);
    let inspect = json!({
        "schema": model::SCHEMA,
        "source": "smcb-ee-test-only.pem",
        "certificates": [inspected],
        "pkcs12": null,
    });
    conforms("../ti-cli/schemas/pki-inspect.json", &inspect);
    let fields = report["certificates"][0].as_object().unwrap();
    assert!(!fields.contains_key("not_before_at"));
    assert!(!fields.contains_key("not_after_at"));
}

#[cfg(all(feature = "load", feature = "brainpool", feature = "rsa"))]
mod offline {
    use ti_pki::offline::{self, TslFailure};
    use ti_pki::tsl_signature::DetachedTsl;
    use ti_pki::{Env, TrustConfig};

    use super::*;

    fn prod(suffix: &str) -> Vec<u8> {
        read(&format!(
            "../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}"
        ))
    }

    fn tampered() -> Vec<u8> {
        let mut xml = prod("xml");
        let at = xml.len() / 2;
        xml[at] ^= 0x01;
        xml
    }

    fn view(xml: &[u8], signer_status: Option<&[u8]>) -> model::Tsl {
        let sig = prod("sig");
        let files = DetachedTsl {
            signature: &sig,
            signer_status,
        };
        let config = TrustConfig::preset_prod();
        let verified = offline::Tsl::verify(xml, files, Env::Prod, &config, None, now());
        model::Tsl::new(Env::Prod, &verified, now())
    }

    fn check(xml: &[u8]) -> (offline::Check, model::Check) {
        let check = offline::Check::new(
            Env::Prod,
            TrustConfig::preset_prod(),
            None,
            xml,
            &prod("sig"),
            now(),
        );
        let certs = [smcb()];
        let outcome = check.check(&certs, now());
        let report = model::Check::new(&check, &certs, &outcome, now());
        (check, report)
    }

    #[test]
    fn the_view_of_the_published_production_tsl_is_valid_and_as_published() {
        let view = view(&prod("xml"), Some(&prod("ocsp")));
        assert_eq!(view.result, "valid");
        assert_eq!(view.environment, "prod");
        assert_eq!(view.tier, "prod");
        assert!(view.error.is_none());
        let roots = view.roots.as_ref().unwrap();
        assert_eq!(roots.source, "embedded");
        assert!(!roots.trusted.is_empty());
        // Certificates are filed under their fingerprint.
        for (key, cert) in &view.certificates {
            assert_eq!(key.len(), 64);
            assert_eq!(*key, cert.sha256.replace(':', "").to_lowercase());
        }
        #[cfg(feature = "serde")]
        conforms(
            "../ti-wasm/schemas/tsl-view.json",
            &serde_json::to_value(&view).unwrap(),
        );
    }

    #[test]
    fn the_view_of_a_tampered_list_is_the_verdict_only() {
        let view = view(&tampered(), None);
        assert_eq!(view.result, "invalid");
        let error = view.error.as_ref().unwrap();
        assert_eq!(error.rule, "TSLDET-005");
        assert!(view.list.is_none());
        assert!(view.certificates.is_empty());
        #[cfg(feature = "serde")]
        conforms(
            "../ti-wasm/schemas/tsl-view.json",
            &serde_json::to_value(&view).unwrap(),
        );
    }

    /// Roots that do not verify leave nothing of the list to show.
    #[test]
    fn a_roots_failure_is_the_verdict_only() {
        let failed = Err(TslFailure::Roots("embedded roots.json: broken".to_owned()));
        let view = model::Tsl::new(Env::Prod, &failed, now());
        assert_eq!(view.result, "invalid");
        let error = view.error.as_ref().unwrap();
        assert_eq!((error.code, error.rule), ("roots_error", "A_28419"));
        assert!(view.roots.is_none() && view.providers.is_empty());
    }

    #[test]
    fn a_check_against_the_production_tsl_reports_its_trust_material() {
        let (_, report) = check(&prod("xml"));
        assert_eq!(report.tsl.result, "valid");
        assert_eq!(report.tsl.roots_source, "embedded");
        assert!(report.tsl.error.is_none());
        assert!(report.tsl.sequence_number.is_some());

        // A TEST-ONLY certificate has no place in production; the report says so and still
        // shows the certificate as `ti pki inspect` would.
        assert_eq!(report.result, "invalid");
        assert_eq!(report.environment, "prod");
        assert_eq!(report.revocation, "not_checked");
        assert_eq!(report.profile.as_ref().unwrap().name, "hci-aut");
        assert_eq!(report.certificate_type.as_deref(), Some("C.HCI.AUT"));
        assert!(!report.errors.is_empty());
        assert_eq!(report.certificates.len(), 1);
        assert_eq!(report.certificates[0].sha256, smcb().fingerprint_sha256());
        assert!(!report.tree.is_empty());
        #[cfg(feature = "serde")]
        conforms(
            "../ti-wasm/schemas/check.json",
            &serde_json::to_value(&report).unwrap(),
        );
    }

    #[test]
    fn a_check_against_an_invalid_tsl_trusts_nothing() {
        let (check, report) = check(&tampered());
        let state = model::TslState::new(check.material());
        assert_eq!(state.result, "invalid");
        assert_eq!(state.error.as_ref().unwrap().rule, "TSLDET-005");

        assert_eq!(report.result, "invalid");
        let codes: Vec<&str> = report.errors.iter().map(|e| e.code).collect();
        assert_eq!(codes, ["tsl_invalid"]);
        assert_eq!(report.tree.len(), 1);
        assert_eq!(report.tree[0].state, "bad");
        #[cfg(feature = "serde")]
        conforms(
            "../ti-wasm/schemas/check.json",
            &serde_json::to_value(&report).unwrap(),
        );
    }
}
