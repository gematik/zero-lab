//! `ti identity` and `ti pki verify-signature`: the SMC-B identity the way ePA and the
//! IDP-Dienst use it, through the binary as a script or `epa` would call it.

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use jwz::jws::Jws;
use jwz::profile::Profile;
use jwz_brainpool::BrainpoolEs256Key;
use serde_json::{Value, json};
use support::assert_conforms;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/identity")
        .join(name)
}

fn fixture_str(name: &str) -> String {
    fixture(name).to_string_lossy().into_owned()
}

/// A directory of this test's own, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ti-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ti"));
    cmd.args(["--format", "json"])
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env_remove("TI_P12_PASSWORD_PATH")
        .env(
            "TI_CACHE_DIR",
            std::env::temp_dir().join("ti-tests-no-cache"),
        )
        .env(
            "XDG_STATE_HOME",
            std::env::temp_dir().join("ti-tests-state"),
        );
    cmd
}

fn ti(args: &[&str]) -> Output {
    command(args).output().unwrap()
}

fn ti_with_stdin(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = command(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn error_kind(out: &Output) -> String {
    assert_conforms("error", &out.stderr);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    error["error"]["kind"].as_str().unwrap().to_owned()
}

fn der_of(pem: &Path) -> Vec<u8> {
    ti_pki::parse_pem_certificates(&std::fs::read(pem).unwrap())
        .unwrap()
        .remove(0)
        .der()
        .to_vec()
}

/// `aut.p12`, `osig.p12` and `enc.p12` merged into one file, as a card vendor's
/// PKCS#12 holds all three identities of an SMC-B.
fn merged_p12(dir: &TempDir) -> String {
    let mut merged = ti_pkcs12::Pkcs12::default();
    for name in ["osig", "enc", "aut"] {
        let bytes = std::fs::read(fixture(&format!("{name}.p12"))).unwrap();
        let p12 = ti_pkcs12::decode(&bytes, "00").unwrap();
        for cert in p12.certificates {
            if cert.local_key_id.is_some() || !merged.certificates.contains(&cert) {
                merged.certificates.push(cert);
            }
        }
        merged.keys.extend(p12.keys);
    }
    let mut counter = 0u8;
    let encoded = ti_pkcs12::encode(&merged, "00", |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            counter = counter.wrapping_add(1);
            *b = counter;
        }
    })
    .unwrap();
    dir.file("identity.p12", &encoded)
}

fn assert_is_the_aut_identity(report: &Value) {
    assert_eq!(report["schema"], 1);
    assert_eq!(report["telematik_id"], "1-2-ARZTPRAXIS-TESTONLY01");
    assert_eq!(report["signing"]["alg"], "ES256");
    assert_eq!(report["signing"]["curve"], "brainpoolP256r1");
    let certificate = &report["certificate"];
    assert_eq!(
        certificate["subject"],
        "CN=Arztpraxis TEST-ONLY,O=gematik TEST-ONLY,C=DE"
    );
    assert_eq!(certificate["key_usage"], json!(["digitalSignature"]));
    assert_eq!(
        certificate["admission"]["registration_number"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    assert_eq!(
        certificate["pem"].as_str().unwrap().trim(),
        std::fs::read_to_string(fixture("aut.pem")).unwrap().trim()
    );
    let chain = report["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 1, "the CA, and nothing else: {chain:?}");
    assert_eq!(
        chain[0]["subject"],
        "CN=GEM.SMCB-CA TEST-ONLY,O=gematik TEST-ONLY,C=DE"
    );
}

#[test]
fn inspect_selects_the_aut_pair_of_a_pkcs12_with_several_identities() {
    let dir = TempDir::new("inspect-p12");
    let p12 = merged_p12(&dir);
    let out = ti(&["identity", "inspect", "--p12", &p12]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("identity inspect", &out.stdout);
    let report = json(&out);
    assert_is_the_aut_identity(&report);
    assert_eq!(report["source"]["kind"], "p12");
    assert_eq!(report["source"]["name"], p12.as_str());
}

#[test]
fn inspect_reads_a_pem_certificate_chain_and_key() {
    let out = ti(&[
        "identity",
        "inspect",
        "--cert",
        &fixture_str("aut-chain.pem"),
        "--key",
        &fixture_str("aut.key"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("identity inspect", &out.stdout);
    let report = json(&out);
    assert_is_the_aut_identity(&report);
    assert_eq!(report["source"]["kind"], "pem");
}

#[test]
fn a_file_without_an_aut_pair_is_identity_not_found() {
    for name in ["osig.p12", "enc.p12"] {
        let out = ti(&["identity", "inspect", "--p12", &fixture_str(name)]);
        assert_eq!(out.status.code(), Some(4), "{name}");
        assert_eq!(error_kind(&out), "identity_not_found", "{name}");
    }
    // A key that does not belong to the certificate.
    let out = ti(&[
        "identity",
        "inspect",
        "--cert",
        &fixture_str("aut.pem"),
        "--key",
        &fixture_str("osig.key"),
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_kind(&out), "identity_not_found");
}

#[test]
fn the_p12_password_comes_from_a_file_for_callers() {
    let dir = TempDir::new("password");
    let right = dir.file("password", b"00\n");
    let out = ti(&[
        "identity",
        "inspect",
        "--p12",
        &fixture_str("aut.p12"),
        "--p12-password-path",
        &right,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let wrong = dir.file("wrong", b"not it");
    let out = ti(&[
        "identity",
        "inspect",
        "--p12",
        &fixture_str("aut.p12"),
        "--p12-password-path",
        &wrong,
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_kind(&out), "p12_password");

    let missing = dir.0.join("missing").to_string_lossy().into_owned();
    let out = ti(&[
        "identity",
        "inspect",
        "--p12",
        &fixture_str("aut.p12"),
        "--p12-password-path",
        &missing,
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_kind(&out), "input_unreadable");

    // The environment variable is the same thing.
    let out = command(&["identity", "inspect", "--p12", &fixture_str("aut.p12")])
        .env("TI_P12_PASSWORD_PATH", &wrong)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_kind(&out), "p12_password");

    // `pki inspect` takes the file too.
    let out = ti(&[
        "pki",
        "inspect",
        &fixture_str("aut.p12"),
        "--p12-password-path",
        &right,
    ]);
    assert_eq!(out.status.code(), Some(0));
}

/// The signing input and the raw signature of a compact JWS.
fn split_jws(jws: &str) -> (Vec<u8>, Vec<u8>) {
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "{jws}");
    (
        format!("{}.{}", parts[0], parts[1]).into_bytes(),
        Base64UrlUnpadded::decode_vec(parts[2]).unwrap(),
    )
}

#[test]
fn sign_produces_an_es256_jws_with_x5c_that_the_certificate_verifies() {
    let claims = json!({"nonce": "abc", "iat": 1_700_000_000, "exp": 1_700_001_200});
    let out = ti_with_stdin(
        &[
            "identity",
            "sign",
            "--p12",
            &fixture_str("aut.p12"),
            "--claims",
            "-",
        ],
        claims.to_string().as_bytes(),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("identity sign", &out.stdout);
    let report = json(&out);
    assert_eq!(report["alg"], "ES256");
    assert_eq!(
        report["identity"]["telematik_id"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    let jws = report["jws"].as_str().unwrap();

    let der = der_of(&fixture("aut.pem"));
    let header = &report["header"];
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["x5c"], json!([Base64::encode_string(&der)]));
    let encoded_header: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(jws.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        &encoded_header, header,
        "the report shows the header as sent"
    );

    let certificate = ti_pki::Certificate::from_der(&der).unwrap();
    let key = BrainpoolEs256Key::from_point(certificate.public_key()).unwrap();
    let registry = jwz_brainpool::registry();
    let policy = Profile::rfc7518_interop(&registry).policy;
    let verified = Jws::parse(jws, &policy, &registry)
        .unwrap()
        .verify(&key)
        .unwrap();
    let payload: Value = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(payload, claims);

    // ePA's client attest and entitlement differ only in header and claims.
    let out = ti_with_stdin(
        &[
            "identity",
            "sign",
            "--p12",
            &fixture_str("aut.p12"),
            "--claims",
            "-",
            "--typ",
            "dpop+jwt",
            "--header",
            "kid=aut-1",
            "--header",
            "htm=\"POST\"",
        ],
        br#"{"auditEvidence": "x", "hcv": "aGN2"}"#,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(report["header"]["typ"], "dpop+jwt");
    assert_eq!(report["header"]["kid"], "aut-1");
    assert_eq!(report["header"]["htm"], "POST");
    assert!(report["header"]["x5c"].is_array());
}

#[test]
fn sign_takes_the_claims_from_a_file_and_refuses_what_is_not_an_object() {
    let dir = TempDir::new("claims");
    let claims = dir.file("claims.json", br#"{"a": 1}"#);
    let out = ti(&[
        "identity",
        "sign",
        "--p12",
        &fixture_str("aut.p12"),
        "--claims",
        &claims,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    for bad in [&b"[1]"[..], b"not json", b""] {
        let out = ti_with_stdin(
            &[
                "identity",
                "sign",
                "--p12",
                &fixture_str("aut.p12"),
                "--claims",
                "-",
            ],
            bad,
        );
        assert_eq!(out.status.code(), Some(4), "{bad:?}");
        assert_eq!(error_kind(&out), "claims_invalid", "{bad:?}");
    }

    // `alg` is the key's, never the caller's.
    let out = ti_with_stdin(
        &[
            "identity",
            "sign",
            "--p12",
            &fixture_str("aut.p12"),
            "--claims",
            "-",
            "--header",
            "alg=none",
        ],
        b"{}",
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn verify_signature_takes_der_and_raw_signatures() {
    let dir = TempDir::new("verify-signature");
    let (cert, data, der) = (
        fixture_str("aut.pem"),
        fixture_str("data.bin"),
        fixture_str("sig.der"),
    );
    let out = ti(&[
        "pki",
        "verify-signature",
        "--cert",
        &cert,
        "--data",
        &data,
        "--signature",
        &der,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("pki verify-signature", &out.stdout);
    let report = json(&out);
    assert_eq!(report["valid"], true);
    assert_eq!(report["signature_format"], "der");
    assert_eq!(report["hash"], "SHA-256");
    assert_eq!(
        report["certificate"]["key"]["algorithm"],
        "ECDSA brainpoolP256r1"
    );

    // A raw r‖s signature: what the JWS carries over its signing input.
    let signed = ti_with_stdin(
        &[
            "identity",
            "sign",
            "--p12",
            &fixture_str("aut.p12"),
            "--claims",
            "-",
        ],
        b"{\"n\": 1}",
    );
    let jws = json(&signed)["jws"].as_str().unwrap().to_owned();
    let (signing_input, raw) = split_jws(&jws);
    assert_eq!(raw.len(), 64);
    let input = dir.file("signing-input", &signing_input);
    let raw = dir.file("sig.raw", &raw);
    let out = ti(&[
        "pki",
        "verify-signature",
        "--cert",
        &cert,
        "--data",
        &input,
        "--signature",
        &raw,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(report["valid"], true);
    assert_eq!(report["signature_format"], "raw");
}

#[test]
fn verify_signature_rejects_tampering_other_keys_and_garbage() {
    let dir = TempDir::new("verify-signature-reject");
    let (cert, data, der) = (
        fixture_str("aut.pem"),
        fixture_str("data.bin"),
        fixture_str("sig.der"),
    );

    // Other data: not valid, exit 1, still a report.
    let tampered = dir.file("tampered", b"VAU signed_pub_keys TEST-ONLY tampered\n");
    let out = ti(&[
        "pki",
        "verify-signature",
        "--cert",
        &cert,
        "--data",
        &tampered,
        "--signature",
        &der,
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_conforms("pki verify-signature", &out.stdout);
    assert_eq!(json(&out)["valid"], false);

    // Another key's certificate: not valid either.
    let out = ti(&[
        "pki",
        "verify-signature",
        "--cert",
        &fixture_str("osig.pem"),
        "--data",
        &data,
        "--signature",
        &der,
    ]);
    assert_eq!(out.status.code(), Some(1));

    // Neither DER nor the curve's r‖s: an input error, not a verdict.
    let garbage = dir.file("garbage", &[1, 2, 3, 4, 5]);
    let out = ti(&[
        "pki",
        "verify-signature",
        "--cert",
        &cert,
        "--data",
        &data,
        "--signature",
        &garbage,
    ]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(error_kind(&out), "signature_malformed");
}

#[test]
fn identity_commands_have_published_schemas() {
    for command in ["identity inspect", "identity sign", "pki verify-signature"] {
        let args: Vec<&str> = ["schema"].into_iter().chain(command.split(' ')).collect();
        let out = ti(&args);
        assert_eq!(out.status.code(), Some(0), "{command}");
        let schema = json(&out);
        assert_eq!(schema["title"], command);
    }
}
