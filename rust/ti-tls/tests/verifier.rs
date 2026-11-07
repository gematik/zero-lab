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

//! The verifiers as rustls sees them, and what no corpus file can hold: the handshake
//! parameters of `testdata/handshake.json`, the reuse of verdicts and the refusals.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error, ProtocolVersion};
use serde_json::Value;
use ti_pki::load::MockTransport;
use ti_pki::ocsp::OcspChecker;
use ti_pki::time::FixedClock;
use ti_pki::tls::ServerCheck;
use ti_pki::tsl::Intermediate;
use ti_pki::{CertificateType, Timestamp, TrustConfig, TrustStore};
use ti_tls::verifier::{VERSIONS, provider};
use ti_tls::{Fetch, TiVerifier, WebCheck, WebVerifier, client_config};

/// 2026-01-01T00:00:00Z, the reference time of the corpus.
const AT: u64 = 1_767_225_600;
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-validation/testdata")
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(testdata().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn cert(name: &str) -> ti_pki::Certificate {
    ti_pki::parse_pem_certificates(&bytes(name))
        .unwrap()
        .remove(0)
}

fn der(name: &str) -> CertificateDer<'static> {
    CertificateDer::from(cert(name).der().to_vec())
}

fn at(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(core::time::Duration::from_secs(seconds))
}

fn name(host: &str) -> ServerName<'static> {
    ServerName::try_from(host.to_owned()).unwrap()
}

/// A network for the web verifier that counts what it is asked and answers from a file.
struct Counting {
    ocsp: Option<Vec<u8>>,
    asked: AtomicUsize,
}

impl Fetch for Counting {
    async fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        self.ocsp.clone()
    }

    async fn crl(&self, _: &str) -> Option<Vec<u8>> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        None
    }
}

fn web(ocsp: Option<&str>) -> WebVerifier<Counting> {
    WebVerifier::new(
        WebCheck::new([der("web-root.pem")]),
        Counting {
            ocsp: ocsp.map(bytes),
            asked: AtomicUsize::new(0),
        },
    )
}

/// A network behind an `Rc`, neither `Send` nor `Sync`, as a browser host over JS fetch
/// holds it.
struct Local {
    ocsp: Vec<u8>,
    asked: Rc<Cell<usize>>,
}

impl Fetch for Local {
    async fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        self.asked.set(self.asked.get() + 1);
        Some(self.ocsp.clone())
    }

    async fn crl(&self, _: &str) -> Option<Vec<u8>> {
        self.asked.set(self.asked.get() + 1);
        None
    }
}

type TiResponder = OcspChecker<MockTransport, Box<dyn Fn() -> Timestamp + Send + Sync>>;

/// The corpus's TI trust: its root, and its CA as a verified TSL would list it. The
/// responder answers once, with `answer`, and fails after that; it keeps its answers by
/// `clock`, which the test moves with the handshakes.
fn ti(answer: &str, clock: Arc<FixedClock>) -> TiVerifier<TiResponder> {
    let ca = cert("ti-ca.pem");
    let types = vec![(
        ca.clone(),
        vec![CertificateType::from_str("C.FD.TLS-S").unwrap().oid()],
    )];
    let store = TrustStore::new([cert("ti-root.pem")])
        .with_intermediates(vec![Intermediate {
            certificate: ca,
            provider: "TEST-ONLY".into(),
            revoked_since: None,
        }])
        .with_tsl_ca_types_for_tests(types);
    let config = TrustConfig::for_lab_ca(cert("ti-root.pem").der());
    let responder = OcspChecker::new(
        &config,
        MockTransport::posting([Ok(bytes(answer))]),
        Box::new(move || clock.now()) as Box<dyn Fn() -> Timestamp + Send + Sync>,
    );
    TiVerifier::new(ServerCheck::new(config, Some(Arc::new(store))), responder)
}

fn codes(handshake: &Value, profile: &str, field: &str) -> Vec<u16> {
    let code = |name: &str| -> u16 {
        match name {
            "TLS_AES_128_GCM_SHA256" => 0x1301,
            "TLS_AES_256_GCM_SHA384" => 0x1302,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => 0xc02b,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => 0xc02c,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => 0xc02f,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => 0xc030,
            "secp256r1" => 0x0017,
            "secp384r1" => 0x0018,
            "ecdsa_secp256r1_sha256" => 0x0403,
            "ecdsa_secp384r1_sha384" => 0x0503,
            "ecdsa_brainpoolP256r1tls13_sha256" => 0x081a,
            "ecdsa_brainpoolP384r1tls13_sha384" => 0x081b,
            "rsa_pss_rsae_sha256" => 0x0804,
            "rsa_pss_rsae_sha384" => 0x0805,
            "rsa_pss_rsae_sha512" => 0x0806,
            "rsa_pkcs1_sha256" => 0x0401,
            "rsa_pkcs1_sha384" => 0x0501,
            "rsa_pkcs1_sha512" => 0x0601,
            other => panic!("{other} is not in this table"),
        }
    };
    sorted(
        handshake[profile][field]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| code(n.as_str().unwrap()))
            .collect(),
    )
}

fn sorted(mut codes: Vec<u16>) -> Vec<u16> {
    codes.sort_unstable();
    codes
}

/// TLSV-010, TLSV-011, TLSV-012 and TLSV-013: the configuration offers exactly the versions,
/// suites, groups and signature schemes of `handshake.json`.
#[test]
fn tlsv_011_the_client_offers_what_handshake_json_lists() {
    let handshake: Value = serde_json::from_slice(&bytes("handshake.json")).unwrap();
    let provider = provider();
    let suites = sorted(
        provider
            .cipher_suites
            .iter()
            .map(|s| u16::from(s.suite()))
            .collect(),
    );
    let groups = sorted(
        provider
            .kx_groups
            .iter()
            .map(|g| u16::from(g.name()))
            .collect(),
    );
    for profile in ["ti", "web"] {
        assert_eq!(
            suites,
            codes(&handshake, profile, "cipher_suites"),
            "{profile}"
        );
        assert_eq!(groups, codes(&handshake, profile, "groups"), "{profile}");
    }
    let versions: Vec<ProtocolVersion> = VERSIONS.iter().map(|v| v.version).collect();
    assert_eq!(
        versions,
        [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
    );
    let _: rustls::ClientConfig = client_config(Arc::new(web(None)));
    let schemes = |v: &dyn ServerCertVerifier| {
        sorted(
            v.supported_verify_schemes()
                .into_iter()
                .map(u16::from)
                .collect(),
        )
    };
    assert_eq!(
        schemes(&web(None)),
        codes(&handshake, "web", "signature_schemes")
    );
    assert_eq!(
        schemes(&ti(
            "ocsp/ti-good-good.der",
            Arc::new(FixedClock::new(Timestamp(AT)))
        )),
        codes(&handshake, "ti", "signature_schemes")
    );
}

/// TLSV-050 and TLSV-051: an accepted verdict is reused for the same chain and host until its
/// revocation status is a day old, then the responder is asked again; another host is judged
/// afresh.
#[test]
fn tlsv_050_a_web_verdict_is_reused_until_its_status_is_too_old() {
    let verifier = web(Some("ocsp/web-p256-good.der"));
    let chain = [der("web-p256.pem"), der("web-ca.pem")];
    let host = name("www.web.test");
    let verify = |now| verifier.verify_server_cert(&chain[0], &chain[1..], &host, &[], at(now));
    let asked = || verifier_asked(&verifier);
    assert!(verify(AT).is_ok());
    assert_eq!(asked(), 1);
    assert!(verify(AT + 23 * HOUR).is_ok());
    assert_eq!(asked(), 1, "reused");
    assert!(verify(AT + 24 * HOUR).is_ok());
    assert_eq!(asked(), 2, "a day old: asked again");
    let other =
        verifier.verify_server_cert(&chain[0], &chain[1..], &name("other.web.test"), &[], at(AT));
    assert!(other.is_err());
}

fn verifier_asked(verifier: &WebVerifier<Counting>) -> usize {
    verifier.fetch().asked.load(Ordering::Relaxed)
}

/// `Fetch` carries no `Send` bound so that a browser host can implement it; the web check
/// may not ask for one on its way to the responder. Only rustls's verifier needs `Send`.
#[test]
fn a_fetch_that_is_not_send_drives_the_web_check() {
    let fetch = Local {
        ocsp: bytes("ocsp/web-p256-good.der"),
        asked: Rc::default(),
    };
    let verdict = futures_lite::future::block_on(WebCheck::new([der("web-root.pem")]).verify(
        &[der("web-p256.pem"), der("web-ca.pem")],
        "www.web.test",
        None,
        Timestamp(AT),
        &fetch,
    ));
    assert!(verdict.is_valid(), "{}", verdict.detail);
    assert_eq!(fetch.asked.get(), 1);
}

/// TLSV-050: a refusal is never reused; every handshake asks again.
#[test]
fn tlsv_050_a_refusal_is_judged_again_every_time() {
    let verifier = web(None);
    let chain = [der("web-p256.pem"), der("web-ca.pem")];
    let host = name("www.web.test");
    for round in 1..=3 {
        assert!(
            verifier
                .verify_server_cert(&chain[0], &chain[1..], &host, &[], at(AT))
                .is_err()
        );
        assert_eq!(
            verifier_asked(&verifier),
            2 * round,
            "OCSP and CRL each time"
        );
    }
}

/// TLSV-051: a `ti` verdict rests on its OCSP answer for OCSP-005's hour at most.
#[test]
fn tlsv_051_a_ti_verdict_is_reused_for_the_hour_of_its_ocsp_answer() {
    let clock = Arc::new(FixedClock::new(Timestamp(AT)));
    let verifier = ti("ocsp/ti-good-good.der", Arc::clone(&clock));
    let chain = [der("ti-good.pem"), der("ti-ca.pem")];
    let host = name("svc.ti.test");
    let verify = |now| {
        clock.set(Timestamp(now));
        verifier.verify_server_cert(&chain[0], &chain[1..], &host, &[], at(now))
    };
    assert!(verify(AT).is_ok());
    // The responder has answered its one answer; a second question would fail.
    assert!(verify(AT + 59 * MINUTE).is_ok(), "reused");
    assert!(
        verify(AT + 61 * MINUTE).is_err(),
        "an hour on, the responder is asked again"
    );
}

/// TLSV-050, TLSV-033: the ti verifier's trust material is replaced while a configuration
/// uses it; the verdicts reached with the old material go with it.
#[test]
fn tlsv_050_a_ti_verifiers_trust_material_is_replaced_in_use() {
    let clock = Arc::new(FixedClock::new(Timestamp(AT)));
    let verifier = Arc::new(ti("ocsp/ti-good-good.der", Arc::clone(&clock)));
    let _config = client_config(Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>);
    let chain = [der("ti-good.pem"), der("ti-ca.pem")];
    let host = name("svc.ti.test");
    let verify = || verifier.verify_server_cert(&chain[0], &chain[1..], &host, &[], at(AT));
    assert!(verify().is_ok());
    assert!(verify().is_ok(), "reused");

    let config = TrustConfig::for_lab_ca(cert("ti-root.pem").der());
    verifier.replace(ServerCheck::new(config, None));
    let Err(Error::InvalidCertificate(CertificateError::Other(other))) = verify() else {
        panic!("the cached verdict outlived its material");
    };
    assert!(
        other.to_string().starts_with("trust_material_unavailable"),
        "{other}"
    );
}

/// TLSV-002: a refusal reaches rustls as an error, which ends the handshake with a fatal
/// alert; rustls names what it knows, the rest carries the spec's code.
#[test]
fn tlsv_002_a_refusal_is_a_rustls_error_with_its_reason() {
    let verifier = web(Some("ocsp/web-p256-good.der"));
    let refuse = |leaf: &str, host: &str| {
        verifier
            .verify_server_cert(&der(leaf), &[der("web-ca.pem")], &name(host), &[], at(AT))
            .unwrap_err()
    };
    assert_eq!(
        refuse("web-p256.pem", "other.web.test"),
        Error::InvalidCertificate(CertificateError::NotValidForName)
    );
    assert_eq!(
        refuse("web-expired.pem", "www.web.test"),
        Error::InvalidCertificate(CertificateError::Expired)
    );
    let Error::InvalidCertificate(CertificateError::Other(other)) =
        refuse("web-long.pem", "www.web.test")
    else {
        panic!("validity_too_long has no rustls name");
    };
    assert!(
        other.to_string().starts_with("validity_too_long"),
        "{other}"
    );
}
