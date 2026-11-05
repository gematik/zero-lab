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

//! `spec/pki-path/testdata/validate.json`: the verdicts of this crate's `Validator`, the corpus `go/tipki` is
//! held to. Set `TI_PKI_BLESS=1` to write it again after a deliberate change to a rule.
#![cfg(all(feature = "brainpool", feature = "rsa", feature = "dangerous-nonprod"))]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use ti_pki::error::{ErrorCode, ValidationError};
use ti_pki::profile::PROFILES;
use ti_pki::revocation::{
    ResponderAuthorization, RevocationChecker, RevocationMode, RevocationResult, RevocationStatus,
};
use ti_pki::tsl::Intermediate;
use ti_pki::tsl_signature::DetachedTsl;
use ti_pki::{
    Certificate, CertificateType, Env, Timestamp, TrustConfig, TrustStore, ValidationResult,
    Validator, detect_certificate_type,
};

/// `TestPki::NOW`.
const NOW: u64 = 1_767_225_600;
const TEN_YEARS: u64 = 10 * 366 * 86_400;
const REVOKED_AT: u64 = NOW - 3600;

fn pki() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pki")
}

fn cert(name: &str) -> Certificate {
    let pem = std::fs::read(pki().join(name)).unwrap();
    ti_pki::parse_pem_certificates(&pem).unwrap().remove(0)
}

/// Answers every question with one scripted outcome.
struct Scripted(&'static str);

impl RevocationChecker for Scripted {
    async fn check(
        &self,
        cert: &Certificate,
        _: &Certificate,
        _: &TrustStore,
    ) -> Result<RevocationResult, ValidationError> {
        let mut result = RevocationResult::unknown(Timestamp(NOW), "scripted");
        "scripted responder".clone_into(&mut result.responder_name);
        match self.0 {
            "good" => result.status = RevocationStatus::Good,
            "same_tsp" => {
                result.status = RevocationStatus::Good;
                result.authorization = Some(ResponderAuthorization::SameTspDelegate {
                    ca: "some CA".to_owned(),
                    tsp: "some TSP".to_owned(),
                });
            }
            "revoked" | "revoked_later" => {
                result.status = RevocationStatus::Revoked;
                let at = if self.0 == "revoked" {
                    REVOKED_AT
                } else {
                    NOW + 3600
                };
                result.revoked_at = Some(Timestamp(at));
            }
            "revoked_no_time" => result.status = RevocationStatus::Revoked,
            "unknown" => {}
            "unavailable" | "invalid" | "untrusted" => {
                let code = match self.0 {
                    "unavailable" => ErrorCode::OcspUnavailable,
                    "invalid" => ErrorCode::OcspResponseInvalid,
                    _ => ErrorCode::OcspResponderUntrusted,
                };
                return Err(ValidationError::new(code, "scripted").with_subject(cert.subject_cn()));
            }
            other => panic!("{other}"),
        }
        Ok(result)
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

fn fixtures() -> Vec<(String, Certificate)> {
    let mut names: Vec<String> = Vec::new();
    for (dir, prefix) in [("", ""), ("types", "types/")] {
        for entry in std::fs::read_dir(pki().join(dir)).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if Path::new(&name).extension().is_some_and(|e| e == "pem")
                && !name.starts_with("ocsp-")
            {
                names.push(format!("{prefix}{name}"));
            }
        }
    }
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let c = cert(&name);
            (name, c)
        })
        .collect()
}

fn is_root(name: &str) -> bool {
    matches!(name, "rca1.pem" | "rca7.pem" | "rca-rsa.pem")
}

fn store(all: &[(String, Certificate)], revoked_since: Option<u64>) -> Arc<TrustStore> {
    let intermediates = all
        .iter()
        .filter(|(n, c)| !is_root(n) && c.is_ca() && !n.starts_with("rogue"))
        .map(|(_, c)| Intermediate {
            certificate: c.clone(),
            provider: "TSP".to_owned(),
            revoked_since: revoked_since.map(Timestamp),
        })
        .collect();
    let roots = all
        .iter()
        .filter(|(n, _)| is_root(n))
        .map(|(_, c)| c.clone());
    Arc::new(TrustStore::new(roots).with_intermediates(intermediates))
}

fn config(mode: RevocationMode) -> TrustConfig {
    TrustConfig {
        revocation: mode,
        ..TrustConfig::for_anchor(Vec::new())
    }
}

fn verdict(result: &ValidationResult) -> Value {
    let pair = |code: String, subject: &str| json!([code, subject]);
    json!({
        "valid": result.valid,
        "chain": result.chain.iter().map(Certificate::subject_cn).collect::<Vec<_>>(),
        "positions": result.cert_results.iter().map(|r| r.position.as_str()).collect::<Vec<_>>(),
        "revocation": result.cert_results.iter().map(|r| r.revocation.as_ref().map(|x| x.status.as_str())).collect::<Vec<_>>(),
        "errors": result.errors.iter().map(|e| pair(e.code.to_string(), &e.subject)).collect::<Vec<_>>(),
        "warnings": result.warnings.iter().map(|w| pair(w.code.to_string(), &w.subject)).collect::<Vec<_>>(),
    })
}

fn run(validator: &Validator, certs: &[Certificate], now: u64, script: &'static str) -> Value {
    verdict(&block_on(validator.validate(certs, Timestamp(now), &Scripted(script))).unwrap())
}

fn mode_name(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}

/// What one fixture's cases share.
struct Recorder<'a> {
    name: &'a str,
    certs: Vec<Certificate>,
    cert_type: Option<ti_pki::CertificateType>,
    cases: Vec<Value>,
}

/// What a case varies, besides its validator.
struct Case {
    kind: &'static str,
    profile: &'static str,
    now: u64,
    mode: RevocationMode,
    script: &'static str,
    since: Value,
    fqdn: Value,
    allow_expired: bool,
}

impl Case {
    fn chain(now: u64, mode: RevocationMode, script: &'static str) -> Self {
        Case {
            kind: "chain",
            profile: "",
            now,
            mode,
            script,
            since: Value::Null,
            fqdn: Value::Null,
            allow_expired: false,
        }
    }

    fn profile(name: &'static str, now: u64, mode: RevocationMode, script: &'static str) -> Self {
        Case {
            kind: "profile",
            profile: name,
            ..Case::chain(now, mode, script)
        }
    }
}

impl Recorder<'_> {
    fn push(&mut self, case: &Case, validator: &Validator) {
        self.cases.push(json!({
            "file": self.name, "kind": case.kind, "profile": case.profile,
            "type": self.cert_type.map(ti_pki::CertificateType::as_str), "now": case.now,
            "mode": mode_name(case.mode), "script": case.script, "ca_revoked_since": case.since,
            "fqdn": case.fqdn, "allow_expired": case.allow_expired,
            "verdict": run(validator, &self.certs, case.now, case.script),
        }));
    }

    /// Every profile, at three times.
    fn profiles_over_time(&mut self, plain: &Arc<TrustStore>) {
        let hard = RevocationMode::HardFail;
        for now in [NOW, NOW - TEN_YEARS, NOW + TEN_YEARS] {
            let base = config(hard);
            self.push(
                &Case::chain(now, hard, "good"),
                &Validator::new(&base, Arc::clone(plain)),
            );
            if let Some(t) = self.cert_type {
                for profile in PROFILES {
                    let validator = profile.validator(&base, Arc::clone(plain), t);
                    self.push(&Case::profile(profile.name, now, hard, "good"), &validator);
                }
            }
        }
    }

    /// Every outcome, in every mode.
    fn outcomes(&mut self, plain: &Arc<TrustStore>) {
        const SCRIPTS: [&str; 9] = [
            "good",
            "same_tsp",
            "revoked",
            "revoked_later",
            "revoked_no_time",
            "unknown",
            "unavailable",
            "invalid",
            "untrusted",
        ];
        for mode in [
            RevocationMode::HardFail,
            RevocationMode::SoftFail,
            RevocationMode::Disabled,
        ] {
            for script in SCRIPTS {
                let base = config(mode);
                self.push(
                    &Case::chain(NOW, mode, script),
                    &Validator::new(&base, Arc::clone(plain)),
                );
                let mut sub_ca_skipped = Validator::new(&base, Arc::clone(plain));
                sub_ca_skipped.skip_sub_ca_revocation = true;
                let case = Case {
                    kind: "skip_sub_ca",
                    ..Case::chain(NOW, mode, script)
                };
                self.push(&case, &sub_ca_skipped);
            }
        }
    }

    /// A profile's mode against the configuration's.
    fn profile_modes(&mut self, plain: &Arc<TrustStore>) {
        let Some(t) = self.cert_type else { return };
        for mode in [RevocationMode::SoftFail, RevocationMode::Disabled] {
            let base = config(mode);
            for profile in PROFILES {
                let validator = profile.validator(&base, Arc::clone(plain), t);
                self.push(
                    &Case::profile(profile.name, NOW, mode, "unavailable"),
                    &validator,
                );
            }
        }
    }

    /// A CA the list revoked, the expected name, and expiry allowed.
    fn the_rest(&mut self, all: &[(String, Certificate)], plain: &Arc<TrustStore>) {
        let hard = RevocationMode::HardFail;
        let base = config(hard);
        for since in [NOW - TEN_YEARS, NOW + TEN_YEARS] {
            let case = Case {
                since: json!(since),
                ..Case::chain(NOW, hard, "good")
            };
            self.push(&case, &Validator::new(&base, store(all, Some(since))));
        }
        for fqdn in ["zeta.ti-dienste.de", "ZETA.ti-dienste.de.", "other.example"] {
            let case = Case {
                fqdn: json!(fqdn),
                ..Case::chain(NOW, hard, "good")
            };
            self.push(
                &case,
                &Validator::new(&base, Arc::clone(plain)).with_expected_fqdn(fqdn),
            );
        }
        let mut allowing = Validator::new(&base, Arc::clone(plain));
        allowing.allow_expired = true;
        let case = Case {
            allow_expired: true,
            ..Case::chain(NOW + TEN_YEARS, hard, "good")
        };
        self.push(&case, &allowing);
    }
}

fn matrix() -> Vec<Value> {
    let all = fixtures();
    let plain = store(&all, None);
    let mut cases = Vec::new();
    for (name, leaf) in all.iter().filter(|(n, _)| !is_root(n)) {
        let mut certs = vec![leaf.clone()];
        certs.extend(
            all.iter()
                .filter(|(n, _)| !is_root(n) && n != name)
                .map(|(_, c)| c.clone()),
        );
        let mut recorder = Recorder {
            name,
            certs,
            cert_type: detect_certificate_type(leaf),
            cases: Vec::new(),
        };
        recorder.profiles_over_time(&plain);
        recorder.outcomes(&plain);
        recorder.profile_modes(&plain);
        recorder.the_rest(&all, &plain);
        cases.append(&mut recorder.cases);
    }
    cases
}

/// A real SMC-B under the real reference list, whose stated CA types come into play.
fn real() -> (Vec<Value>, Value, Value, Value, Value) {
    let spec = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref");
    let read = |suffix: &str| std::fs::read(format!("{}{suffix}", spec.display())).unwrap();
    let now = Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap();
    let base = TrustConfig::preset(Env::Ref);
    let (xml, signature) = (read(".xml"), read(".sig"));
    let (store, _) = TrustStore::from_material(
        &base,
        &base.roots,
        &xml,
        DetachedTsl {
            signature: &signature,
            signer_status: None,
        },
        now,
    )
    .unwrap();
    let store = Arc::new(store);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let leaf = ti_pki::parse_pem_certificates(
        &std::fs::read(fixtures.join("smcb-ee-test-only.pem")).unwrap(),
    )
    .unwrap()
    .remove(0);
    let t = detect_certificate_type(&leaf).unwrap();
    let mut cases = Vec::new();
    for profile in PROFILES {
        let validator = profile.validator(&base, Arc::clone(&store), t);
        cases.push(json!({ "profile": profile.name, "verdict": run(&validator, std::slice::from_ref(&leaf), now.0, "good") }));
    }
    let pem = |name: &str| {
        ti_pki::parse_pem_certificates(&std::fs::read(fixtures.join(name)).unwrap())
            .unwrap()
            .remove(0)
    };
    let ca = Certificate::from_der(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/anchors/GEM.TSL-CA28-TEST-ONLY.der"),
        )
        .unwrap(),
    )
    .unwrap();
    let signer = run(
        &ti_pki::profile::TSL_SIG.validator(&base, Arc::clone(&store), CertificateType::TslSig),
        &[pem("tsl-signing-unit-12-test-only.pem"), ca.clone()],
        now.0,
        "good",
    );
    let without_cas = (*store).clone().with_intermediates(Vec::new());
    let unlisted = run(
        &Validator::new(&base, Arc::new(without_cas)),
        &[pem("tsl-ca-ocsp-signer-10-test-only.pem"), ca],
        now.0,
        "good",
    );
    let mut ca_types: Vec<(String, Vec<String>)> = store
        .intermediates()
        .iter()
        .map(|ca| {
            let mut types: Vec<String> = store
                .tsl_types_of(ca)
                .unwrap_or_default()
                .iter()
                .map(ToString::to_string)
                .collect();
            types.sort();
            (ca.subject_cn().to_owned(), types)
        })
        .collect();
    ca_types.sort();
    let authorized: Vec<&str> = CertificateType::ALL
        .into_iter()
        .filter(|t| *t != CertificateType::TslSig)
        .filter(|t| {
            let named = Validator {
                cert_type: Some(*t),
                ..Validator::new(&base, Arc::clone(&store))
            };
            let verdict = run(&named, std::slice::from_ref(&leaf), now.0, "good");
            !verdict["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e[0] == "cert_type_ca_not_authorized")
        })
        .map(CertificateType::as_str)
        .collect();
    (cases, signer, unlisted, json!(ca_types), json!(authorized))
}

/// What the real list states decides what a CA is for: VALID-007 reads these, so a wrong reading
/// of the list shows here first.
fn assert_real_families(ca_types: &Value) {
    let stated = |needle: &str, excluded: &str| -> Vec<&Vec<Value>> {
        ca_types
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| {
                let name = e[0].as_str().unwrap();
                name.contains(needle) && !name.contains(excluded)
            })
            .map(|e| e[1].as_array().unwrap())
            .collect()
    };
    let oids = |last: &[u32]| -> Vec<String> {
        last.iter().map(|n| format!("1.2.276.0.76.4.{n}")).collect()
    };
    for (family, excluded, want) in [
        ("SMCB-CA", "\0", oids(&[76, 77, 78])),
        ("HBA-CA", "\0", oids(&[74, 75])),
        ("EGK-CA", "ALVI", oids(&[68, 69, 70, 71])),
    ] {
        let found = stated(family, excluded);
        assert!(!found.is_empty(), "{family}");
        for types in found {
            let mut names: Vec<String> = types
                .iter()
                .map(|o| o.as_str().unwrap().to_owned())
                .collect();
            names.sort();
            let mut wanted = want.clone();
            wanted.sort();
            assert_eq!(names, wanted, "{family}");
        }
    }
    for types in stated("KOMP-CA", "\0") {
        for wanted in oids(&[79, 80, 82]) {
            assert!(types.iter().any(|o| o == &json!(wanted)), "KOMP-CA");
        }
    }
}

/// VALID-001, VALID-002, VALID-003 and VALID-007: the corpus is what this crate says.
#[test]
fn valid_001_the_corpus_is_what_ti_pki_says() {
    let (real, signer, unlisted, ca_types, authorized) = real();
    assert_real_families(&ca_types);
    assert_eq!(authorized, json!(["C.HCI.AUT", "C.HCI.ENC", "C.HCI.OSIG"]));
    let hci = real.iter().find(|c| c["profile"] == "hci-aut").unwrap();
    assert_eq!(hci["verdict"]["valid"], true, "{hci}");
    // The list names GEM.TSL-CA28, so its signer stands; with the list's CAs taken out, the same
    // CA, supplied and signed by a root, does not.
    assert_eq!(signer["chain"].as_array().unwrap().len(), 3, "{signer}");
    assert_eq!(signer["valid"], true, "{signer}");
    assert!(
        unlisted["errors"]
            .as_array()
            .unwrap()
            .contains(&json!(["ca_not_in_tsl", "GEM.TSL-CA28 TEST-ONLY"])),
        "{unlisted}"
    );
    let corpus = json!({ "matrix": matrix(), "real": real, "signer": signer, "unlisted": unlisted, "ca_types": ca_types, "authorized": authorized });
    let written = serde_json::to_string(&corpus).unwrap() + "\n";
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-path/testdata/validate.json");
    if std::env::var_os("TI_PKI_BLESS").is_some() {
        std::fs::write(&path, written).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(&path).expect("TI_PKI_BLESS=1 writes the corpus");
    assert_eq!(
        stored, written,
        "the corpus differs: TI_PKI_BLESS=1 after a deliberate change"
    );
}
