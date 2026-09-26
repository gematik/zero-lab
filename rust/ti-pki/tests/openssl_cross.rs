//! Cross-validation against the `openssl` CLI: for every scenario, OpenSSL and
//! `ti-pki` must reach the same verdict on the same bytes. OpenSSL checks what
//! RFC 5280 covers (signatures, validity, CA flags, path length), so `ti-pki` runs
//! without end-entity requirements or revocation here; OCSP responses are compared on
//! authorization and status.
//!
//! Skipped, with a note, when `openssl` is not installed or lacks brainpool curves.
#![cfg(feature = "brainpool")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use futures_lite::future::block_on;
use ti_pki::ocsp::{ResponseCheck, verify_response};
use ti_pki::revocation::{RevocationMode, RevocationStatus, Unchecked};
use ti_pki::tsl::{self, Tsl};
use ti_pki::{Certificate, Timestamp, TrustConfig, TrustStore, Validator, roots};

/// `TestPki::NOW`, the instant the OpenSSL test PKI is built around.
const NOW: Timestamp = Timestamp(1_767_225_600);

fn openssl_available() -> bool {
    let curves = Command::new("openssl")
        .args(["ecparam", "-list_curves"])
        .output();
    let available = curves.is_ok_and(|out| {
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("brainpoolP256r1")
    });
    if !available {
        eprintln!("skipped: openssl with brainpool support not found");
    }
    available
}

fn pki(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pki")
        .join(format!("{name}.pem"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load(path: &Path) -> Vec<Certificate> {
    ti_pki::parse_pem_certificates(&std::fs::read(path).unwrap()).unwrap()
}

/// A scratch file holding `certs` as PEM, removed on drop.
struct Bundle(PathBuf);

impl Bundle {
    fn new(tag: &str, certs: &[Certificate]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ti-pki-openssl-{}-{tag}-{:?}.pem",
            std::process::id(),
            std::thread::current().id()
        ));
        let pem: String = certs.iter().map(pem).collect();
        std::fs::write(&path, pem).unwrap();
        Bundle(path)
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pem(cert: &Certificate) -> String {
    use base64ct::{Base64, Encoding};
    let b64 = Base64::encode_string(cert.der());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// `openssl verify` of `leaf` through `intermediates` to `roots`; `at` is `None` to
/// skip the validity check.
fn openssl_verify(
    leaf: &Certificate,
    intermediates: &[Certificate],
    roots: &[Certificate],
    at: Option<Timestamp>,
) -> (bool, String) {
    let (leaf_file, roots_file) = (
        Bundle::new("leaf", std::slice::from_ref(leaf)),
        Bundle::new("roots", roots),
    );
    let untrusted = Bundle::new("untrusted", intermediates);
    let mut command = Command::new("openssl");
    command.arg("verify").arg("-CAfile").arg(&roots_file.0);
    if !intermediates.is_empty() {
        command.arg("-untrusted").arg(&untrusted.0);
    }
    match at {
        Some(at) => command.args(["-attime", &at.0.to_string()]),
        None => command.arg("-no_check_time"),
    };
    let out = command.arg(&leaf_file.0).output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn ti_pki_verify(
    leaf: &Certificate,
    intermediates: &[Certificate],
    roots: &[Certificate],
    at: Timestamp,
) -> (bool, String) {
    let config = TrustConfig {
        revocation: RevocationMode::Disabled,
        ..TrustConfig::for_anchor(roots[0].der().to_vec())
    };
    let store = Arc::new(TrustStore::new(roots.iter().cloned()));
    let certs: Vec<Certificate> = std::iter::once(leaf.clone())
        .chain(intermediates.iter().cloned())
        .collect();
    let result = block_on(Validator::new(&config, store).validate(&certs, at, &Unchecked)).unwrap();
    let errors: Vec<String> = result.errors.iter().map(ToString::to_string).collect();
    (result.valid, errors.join("; "))
}

fn assert_agree(scenario: &str, leaf: &str, intermediates: &[&str], roots: &[&str], valid: bool) {
    let leaf = &load(&pki(leaf))[0];
    let intermediates: Vec<Certificate> =
        intermediates.iter().flat_map(|n| load(&pki(n))).collect();
    let roots: Vec<Certificate> = roots.iter().flat_map(|n| load(&pki(n))).collect();
    let (openssl, openssl_out) = openssl_verify(leaf, &intermediates, &roots, Some(NOW));
    let (ours, ours_out) = ti_pki_verify(leaf, &intermediates, &roots, NOW);
    assert_eq!(openssl, valid, "{scenario}: openssl says {openssl_out}");
    assert_eq!(ours, valid, "{scenario}: ti-pki says {ours_out}");
}

#[test]
fn test_pki_verdicts_agree() {
    if !openssl_available() {
        return;
    }
    for (scenario, leaf, intermediates, roots, valid) in [
        ("NIST", "ee-zeta", &["sub-ca-komp"][..], &["rca7"][..], true),
        ("brainpool", "ee-arzt", &["sub-ca-hba"], &["rca1"], true),
        (
            "mixed curves",
            "ee-mixed",
            &["sub-ca-mixed"],
            &["rca1"],
            true,
        ),
        ("RSA-PSS", "ee-rsa-pss", &[], &["rca-rsa"], true),
        ("wrong root", "ee-arzt", &["sub-ca-hba"], &["rca7"], false),
        ("rogue root", "ee-rogue", &["rogue-root"], &["rca1"], false),
        (
            "expired end entity",
            "ee-expired",
            &["sub-ca-hba"],
            &["rca1"],
            false,
        ),
        (
            "not yet valid",
            "ee-not-yet-valid",
            &["sub-ca-hba"],
            &["rca1"],
            false,
        ),
        (
            "expired CA",
            "ee-under-expired",
            &["sub-ca-expired"],
            &["rca1"],
            false,
        ),
        (
            "path length",
            "ee-deep",
            &["sub-sub-ca", "sub-ca-pathlen0"],
            &["rca1"],
            false,
        ),
        (
            "end entity as issuer",
            "ee-under-ee",
            &["ee-arzt", "sub-ca-hba"],
            &["rca1"],
            false,
        ),
    ] {
        assert_agree(scenario, leaf, intermediates, roots, valid);
    }
}

#[test]
fn real_smcb_chain_agrees() {
    if !openssl_available() {
        return;
    }
    let leaf = &load(&fixture("admission-1.pem"))[0];
    let ca = load(&fixture("smcb-ca51-test-only.pem"));
    let root = load(&fixture("rca5-test-only.pem"));
    // 2026-06-01, within the validity of all three.
    let at = Timestamp(1_780_272_000);
    let (openssl, out) = openssl_verify(leaf, &ca, &root, Some(at));
    assert!(openssl, "openssl: {out}");
    let (ours, out) = ti_pki_verify(leaf, &ca, &root, at);
    assert!(ours, "ti-pki: {out}");
}

/// Every CA of the production TSL that `match_to_roots` keeps, openssl verifies under
/// the production roots, and every one it rejects, openssl rejects too. Validity is
/// left out on both sides, as `match_to_roots` leaves it to path validation.
#[test]
fn tsl_matching_agrees() {
    if !openssl_available() {
        return;
    }
    let list = Tsl::parse(&std::fs::read(fixture("tsl/ECC-RSA_TSL.xml")).unwrap()).unwrap();
    let config = TrustConfig::preset_prod();
    let roots = roots::load(&config, list.issued_at).unwrap().trusted;
    let store = TrustStore::new(roots.iter().cloned());
    let matched = tsl::match_to_roots(list.intermediate_cas(), &store, &config.algorithms);
    assert!(!matched.intermediates.is_empty());
    for ca in matched.intermediates.iter().map(|i| &i.certificate) {
        let (ok, out) = openssl_verify(ca, &[], &roots, None);
        assert!(ok, "kept {:?}, openssl: {out}", ca.subject_cn());
    }
    for (ca, reason) in matched.rejected.iter().map(|(i, r)| (&i.certificate, r)) {
        let (ok, _) = openssl_verify(ca, &[], &roots, None);
        assert!(
            !ok,
            "rejected {:?} ({reason}), openssl accepts",
            ca.subject_cn()
        );
    }
}

/// `openssl ocsp` and `verify_response` agree on who may sign and on the status. The
/// time window is disabled on the OpenSSL side, which checks it against the wall clock.
#[test]
fn ocsp_verdicts_agree() {
    if !openssl_available() {
        return;
    }
    let cas: Vec<Certificate> = ["rca1", "sub-ca-hba", "rca7", "sub-ca-komp"]
        .iter()
        .flat_map(|n| load(&pki(n)))
        .collect();
    let ca_file = Bundle::new("ocsp-cas", &cas);
    for (response, cert, issuer, status) in [
        (
            "good",
            "ee-arzt",
            "sub-ca-hba",
            Some(RevocationStatus::Good),
        ),
        (
            "revoked",
            "ee-revoked",
            "sub-ca-hba",
            Some(RevocationStatus::Revoked),
        ),
        (
            "issuer-signed",
            "sub-ca-hba",
            "rca1",
            Some(RevocationStatus::Good),
        ),
        ("no-eku", "ee-arzt", "sub-ca-hba", None),
        ("foreign-responder", "ee-arzt", "sub-ca-hba", None),
        ("expired-responder", "ee-arzt", "sub-ca-hba", None),
    ] {
        let der_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pki/ocsp")
            .join(format!("{response}.der"));
        let out = Command::new("openssl")
            .args(["ocsp", "-respin"])
            .arg(&der_path)
            .arg("-CAfile")
            .arg(&ca_file.0)
            .arg("-issuer")
            .arg(pki(issuer))
            // The fixtures' CertIDs are SHA-256; openssl looks the status up by one.
            .arg("-sha256")
            .arg("-cert")
            .arg(pki(cert))
            .args(["-attime", &(NOW.0 + 10).to_string()])
            .args(["-validity_period", "999999999"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        let openssl_status = text.contains("Response verify OK").then(|| {
            if text.contains(": revoked") {
                RevocationStatus::Revoked
            } else {
                assert!(text.contains(": good"), "{response}: {text}");
                RevocationStatus::Good
            }
        });
        let (cert, issuer) = (&load(&pki(cert))[0], &load(&pki(issuer))[0]);
        let der = std::fs::read(&der_path).unwrap();
        let check = ResponseCheck::new(NOW, ti_pki::algorithms::DEFAULT);
        let ours = verify_response(&der, cert, issuer, &check)
            .ok()
            .map(|r| r.status);
        assert_eq!(openssl_status, status, "{response}: openssl says {text}");
        assert_eq!(ours, status, "{response}: ti-pki disagrees");
    }
}
