//! `ti idpd authenticate` end to end against an IDP-Dienst on the loopback that signs
//! with ti-idpd's TEST-ONLY signer: the binary, its ureq transport, the identity from
//! the fixtures, and the IDP's answers as gemSpec_IDP_Dienst describes them.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use base64ct::{Base64UrlUnpadded, Encoding};
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::jws;
use jwz::keys::{SoftwareAgreementKey, SoftwareKey};
use serde_json::{Value, json};
use support::assert_conforms;

type Backend = jwz::crypto::Extended<RustCrypto>;

fn backend() -> Arc<Backend> {
    Arc::new(jwz_brainpool::backend(RustCrypto::new()))
}

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// ti-idpd's TEST-ONLY IDP signer under `kid`, and its certificate.
fn idp_signer(kid: &str) -> (SoftwareKey<Backend>, Vec<u8>) {
    let dir = manifest("../ti-idpd/tests/fixtures");
    let cert = ti_pki::parse_pem_certificates(&std::fs::read(dir.join("idp-sig.pem")).unwrap())
        .unwrap()
        .remove(0);
    let pem = std::fs::read(dir.join("idp-sig.key")).unwrap();
    let (_, der) = pem_rfc7468::decode_vec(&pem).unwrap();
    let scalar = sec1::EcPrivateKey::try_from(der.as_slice())
        .unwrap()
        .private_key
        .to_vec();
    let mut material = EcKey::from_point("BP-256", cert.public_key());
    material.d = Some(Secret::new(scalar));
    let key = SoftwareKey::from_jwk(
        &Jwk::new(KeyMaterial::Ec(material)),
        jwz_brainpool::BP256R1,
        &jwz_brainpool::registry(),
        backend(),
    )
    .unwrap()
    .with_kid(kid);
    (key, cert.der().to_vec())
}

/// What the fake does when the challenge is answered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Code,
    Refuse,
}

/// An IDP-Dienst on 127.0.0.1, one request per connection, until dropped.
struct FakeIdp {
    base_url: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Vec<String>>>,
}

impl FakeIdp {
    fn start(answer: Answer) -> FakeIdp {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let stop = Arc::new(AtomicBool::new(false));
        let (disc_sig, disc_cert) = idp_signer("puk_disc_sig");
        let (idp_sig, _) = idp_signer("puk_idp_sig");
        let mut idp_enc = SoftwareAgreementKey::generate(jwz_brainpool::BP_256, backend())
            .unwrap()
            .public_jwk();
        idp_enc.kid = Some("puk_idp_enc".into());
        let served_from = base_url.clone();
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut posted = Vec::new();
            listener.set_nonblocking(true).unwrap();
            while !stopping.load(Ordering::Relaxed) {
                let Ok((stream, _)) = listener.accept() else {
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                let (method, path, body) = read_request(&stream);
                let response = match (method.as_str(), path.split('?').next().unwrap()) {
                    ("GET", "/.well-known/openid-configuration") => {
                        let metadata = json!({
                            "issuer": served_from,
                            "authorization_endpoint": format!("{served_from}/sign_response"),
                            "token_endpoint": format!("{served_from}/token"),
                            "uri_puk_idp_sig": format!("{served_from}/idpSig/jwk.json"),
                            "uri_puk_idp_enc": format!("{served_from}/idpEnc/jwk.json"),
                            "iat": now() - 60, "exp": now() + 86_400,
                        });
                        let token = jws::sign(
                            metadata.to_string().as_bytes(),
                            HeaderParams::new().typ("JWT").x5c(&[&disc_cert]),
                            &disc_sig,
                        )
                        .unwrap();
                        http(200, "application/jwt", token.as_bytes(), None)
                    }
                    ("GET", "/idpSig/jwk.json") => http(
                        200,
                        "application/json",
                        idp_sig.public_jwk().to_json().as_bytes(),
                        None,
                    ),
                    ("GET", "/idpEnc/jwk.json") => {
                        http(200, "application/json", idp_enc.to_json().as_bytes(), None)
                    }
                    ("GET", "/sign_response") => {
                        let claims = json!({
                            "iss": served_from, "iat": now() - 1, "exp": now() + 180,
                            "token_type": "challenge", "jti": "j1", "snc": "snc",
                            "scope": "openid e-rezept", "code_challenge": "c", "code_challenge_method": "S256",
                            "response_type": "code", "redirect_uri": "https://rp.test/cb",
                            "client_id": "gematikTestPs", "state": "s1", "nonce": "n1",
                        });
                        let challenge = jws::sign(
                            claims.to_string().as_bytes(),
                            HeaderParams::new().typ("JWT"),
                            &idp_sig,
                        )
                        .unwrap();
                        let body = json!({"challenge": challenge, "user_consent": {"requested_scopes": {}, "requested_claims": {}}});
                        http(200, "application/json", body.to_string().as_bytes(), None)
                    }
                    ("POST", "/sign_response") => {
                        posted.push(body);
                        match answer {
                            Answer::Code => http(
                                302,
                                "text/plain",
                                b"",
                                Some("https://rp.test/cb?code=CODE.from.idp&state=s1"),
                            ),
                            Answer::Refuse => http(
                                302,
                                "text/plain",
                                b"",
                                Some(
                                    "https://rp.test/cb?error=access_denied&gematik_error_text=Karte+unbekannt&gematik_code=2030&gematik_timestamp=1&gematik_uuid=u1&state=s1",
                                ),
                            ),
                        }
                    }
                    other => http(404, "text/plain", format!("{other:?}").as_bytes(), None),
                };
                let mut stream = stream;
                stream.write_all(&response).unwrap();
                let _ = stream.flush();
            }
            posted
        });
        FakeIdp {
            base_url,
            stop,
            thread: Some(thread),
        }
    }

    fn stop(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for FakeIdp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Method, target and body of one HTTP/1.1 request.
fn read_request(stream: &TcpStream) -> (String, String, String) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(value) = header
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.trim())
        {
            length = value.parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    (method, path, String::from_utf8(body).unwrap())
}

fn http(status: u16, content_type: &str, body: &[u8], location: Option<&str>) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        _ => "Not Found",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(location) = location {
        out.push_str("Location: ");
        out.push_str(location);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn ti(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["--format", "json"])
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env_remove("TI_P12_PASSWORD_PATH")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY")
        .env(
            "TI_CACHE_DIR",
            std::env::temp_dir().join("ti-tests-no-cache"),
        )
        .output()
        .unwrap()
}

fn identity_fixture(name: &str) -> String {
    manifest("tests/fixtures/identity")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn authenticate_turns_an_authorization_url_into_a_code() {
    let idp = FakeIdp::start(Answer::Code);
    let auth_url = format!(
        "{}/sign_response?client_id=gematikTestPs&response_type=code&state=s1",
        idp.base_url
    );
    let out = ti(&[
        "idpd",
        "authenticate",
        "--idp-url",
        &idp.base_url,
        "--auth-url",
        &auth_url,
        "--p12",
        &identity_fixture("aut.p12"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("idpd authenticate", &out.stdout);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["code"], "CODE.from.idp");
    assert_eq!(report["state"], "s1");
    assert_eq!(report["idp"]["issuer"], idp.base_url);
    assert_eq!(
        report["identity"]["telematik_id"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    assert_eq!(report["challenge"]["client_id"], "gematikTestPs");
    assert_eq!(report["warnings"], json!(["idp_certificates_unverified"]));

    // The IDP received one signed challenge: a JWE for PuK_IDP_ENC with the profile's
    // header.
    let posted = idp.stop();
    assert_eq!(posted.len(), 1);
    let token = posted[0].strip_prefix("signed_challenge=").unwrap();
    let header: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(token.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A256GCM");
    assert_eq!(header["cty"], "NJWT");
    assert_eq!(header["kid"], "puk_idp_enc");
    assert_eq!(header["epk"]["crv"], "BP-256");
}

#[test]
fn the_idps_refusal_is_an_idpd_error_with_its_text() {
    let idp = FakeIdp::start(Answer::Refuse);
    let auth_url = format!("{}/sign_response?client_id=x", idp.base_url);
    let out = ti(&[
        "idpd",
        "authenticate",
        "--idp-url",
        &idp.base_url,
        "--auth-url",
        &auth_url,
        "--cert",
        &identity_fixture("aut-chain.pem"),
        "--key",
        &identity_fixture("aut.key"),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_conforms("error", &out.stderr);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "idpd_error");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("access_denied"), "{message}");
    assert!(message.contains("Karte unbekannt"), "{message}");
    assert!(message.contains("2030"), "{message}");
}

#[test]
fn the_urls_and_the_environment_are_checked_before_anything_is_sent() {
    let p12 = identity_fixture("aut.p12");
    let out = ti(&[
        "idpd",
        "authenticate",
        "--env",
        "ref",
        "--auth-url",
        "ftp://idp/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "not https");

    let out = ti(&[
        "idpd",
        "authenticate",
        "--auth-url",
        "https://idp.test/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "no environment and no IDP URL");

    let out = ti(&[
        "idpd",
        "authenticate",
        "--env",
        "auto",
        "--auth-url",
        "https://idp.test/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "auto has nothing to detect from"
    );
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "environment_invalid");
}

/// `identity sign --alg BP256R1`: the IDP's name for the same ECDSA, on the same key.
#[test]
fn identity_sign_takes_the_idp_algorithm_name() {
    let claims = std::env::temp_dir().join(format!("ti-idpd-claims-{}.json", std::process::id()));
    std::fs::write(&claims, br#"{"njwt": "x"}"#).unwrap();
    let out = ti(&[
        "identity",
        "sign",
        "--p12",
        &identity_fixture("aut.p12"),
        "--claims",
        &claims.to_string_lossy(),
        "--alg",
        "BP256R1",
        "--typ",
        "JWT",
        "--header",
        "cty=NJWT",
    ]);
    let _ = std::fs::remove_file(&claims);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["alg"], "BP256R1");
    assert_eq!(report["header"]["alg"], "BP256R1");
    assert_eq!(report["header"]["cty"], "NJWT");
}
