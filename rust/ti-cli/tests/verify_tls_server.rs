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

//! `ti pki verify --connect …`'s TLS server verdict under the `web` TLS profile, against TLS
//! servers on 127.0.0.1 with a test root (`--cacert`, standing in for the system's) at the
//! instant their certificates and OCSP responses were made for (`--at`): the verdict, the
//! warnings, the revocation source, auto's choice of profile, the exit code and the JSON
//! contract, whichever schema the output is under.

mod support;

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;

use support::{assert_verify_conforms, verify_schema};

/// When the fixtures are valid: their notBefore and the OCSP responses' thisUpdate.
const AT: &str = "2026-01-01T00:00:00Z";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls/web")
        .join(name)
}

fn pem(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    pem_rfc7468::decode_vec(text.as_bytes()).unwrap().1
}

/// A TLS server presenting `leaf` under the test CA, stapling `ocsp` if given, on a port
/// of its own; it completes handshakes until the test ends.
fn serve(leaf: &str, ocsp: Option<&str>) -> u16 {
    let chain = vec![
        CertificateDer::from(pem(&format!("{leaf}.pem"))),
        CertificateDer::from(pem("ca.pem")),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem(&format!("{leaf}.key"))));
    serve_chain(
        chain,
        key,
        ocsp.map(|name| std::fs::read(fixture(name)).unwrap()),
    )
}

/// A TLS server presenting `chain` with `key`, stapling `ocsp` if given, on a port of its
/// own; it completes handshakes until the test ends.
fn serve_chain(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ocsp: Option<Vec<u8>>,
) -> u16 {
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth();
    let config = Arc::new(match ocsp {
        Some(response) => builder
            .with_single_cert_with_ocsp(chain, key, response)
            .unwrap(),
        None => builder.with_single_cert(chain, key).unwrap(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                let _ = conn.complete_io(&mut stream);
                let _ = conn.complete_io(&mut stream);
            });
        }
    });
    port
}

fn ti(args: &[&str]) -> Output {
    let home = std::env::temp_dir().join(format!("ti-verify-web-{}", std::process::id()));
    let root = fixture("root.pem");
    Command::new(env!("CARGO_BIN_EXE_ti"))
        .args([
            "--format",
            "json",
            "--cacert",
            root.to_str().unwrap(),
            "pki",
            "verify",
        ])
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("TI_CACHE_DIR", home.join("cache"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .output()
        .unwrap()
}

/// `ti pki verify --connect` to the server on `port` with `args`, its JSON checked against
/// the schema of what it wrote.
fn connect(port: u16, args: &[&str]) -> (Option<i32>, Value) {
    let target = format!("127.0.0.1:{port}");
    let out = ti(&[&["--connect", target.as_str(), "--at", AT], args].concat());
    assert_verify_conforms(&out.stdout);
    let report = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code(), report)
}

/// The server on `port` under `--validation-profile web`, checked as `name`.
fn verify(port: u16, name: &str) -> (Option<i32>, Value) {
    connect(port, &["--validation-profile", "web", "--fqdn", name])
}

fn warnings(report: &Value) -> Vec<&str> {
    report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect()
}

/// TLSV-040, TLSV-043, TLSV-044: a P-256 server under the test root, its staple good, is
/// valid with no warning and its status from the staple.
#[test]
fn tlsv_044_a_server_with_a_good_staple_is_valid() {
    let port = serve("p256", Some("ocsp/p256-good.der"));
    let (code, report) = verify(port, "www.web.test");
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["tls_profile"], "web");
    assert_eq!(report["profile_reason"], "given");
    assert_eq!(report["server"], format!("127.0.0.1:{port}"));
    assert_eq!(report["valid"], true);
    assert_eq!(report["errors"], serde_json::json!([]));
    assert_eq!(report["host"], "www.web.test");
    assert_eq!(report["at"], AT);
    assert_eq!(
        report["revocation"],
        serde_json::json!({"source": "stapled_ocsp", "stapled": true})
    );
    assert_eq!(
        report["trust"],
        serde_json::json!({"roots": 1, "source": "cacert"})
    );
    assert_eq!(report["chain"][0]["position"], "end_entity");
    assert_eq!(report["chain"].as_array().unwrap().len(), 2);
    assert!(warnings(&report).is_empty(), "{report}");
}

/// TLSV-041: an RSA-2048 server is valid, exit 0, with the warning `key_phased_out`.
#[test]
fn tlsv_041_an_rsa_2048_server_is_valid_with_a_warning() {
    let (code, report) = verify(
        serve("rsa2048", Some("ocsp/rsa2048-good.der")),
        "www.web.test",
    );
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["valid"], true);
    assert_eq!(warnings(&report), ["key_phased_out"]);
    assert_eq!(report["revocation"]["source"], "stapled_ocsp");
}

/// TLSV-044: a server whose certificate names no OCSP responder or CRL and that staples
/// nothing is valid, exit 0, with the warning `revocation_unavailable` and no source.
#[test]
fn tlsv_044_a_server_without_a_revocation_source_is_valid_with_a_warning() {
    let (code, report) = verify(serve("no-status", None), "www.web.test");
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["valid"], true);
    assert_eq!(warnings(&report), ["revocation_unavailable"]);
    assert_eq!(
        report["revocation"],
        serde_json::json!({"source": null, "stapled": false})
    );
}

/// TLSV-043: a name the certificate does not carry is refused, exit 1, with the code.
#[test]
fn tlsv_043_a_wrong_name_is_refused() {
    let (code, report) = verify(serve("p256", Some("ocsp/p256-good.der")), "other.web.test");
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["valid"], false);
    assert_eq!(report["errors"][0]["code"], "name_mismatch");
    assert_eq!(report["revocation"]["source"], Value::Null);
}

/// `web` judges a server: without --connect, or with an option of the TI's validation, it
/// is a usage error (exit 2).
#[test]
fn the_web_profile_needs_connect_and_takes_no_ti_option() {
    let file = fixture("p256.pem");
    let out = ti(&[file.to_str().unwrap(), "--validation-profile", "web"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = ti(&[
        "--connect",
        "127.0.0.1:1",
        "--validation-profile",
        "web",
        "--offline",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// With --connect, auto gives a server whose certificate is not the TI's its TLS server
/// verdict under `web`, and says why.
#[test]
fn auto_takes_a_server_without_a_ti_certificate_to_web() {
    let port = serve("p256", Some("ocsp/p256-good.der"));
    let (code, report) = connect(port, &["--fqdn", "www.web.test"]);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["tls_profile"], "web");
    assert_eq!(
        report["profile_reason"],
        "auto: not a TI certificate, and no ref TSL at hand to check its issuer"
    );
    assert_eq!(report["valid"], true);
}

/// With --connect, auto keeps a server with a TI certificate type with the TI's
/// validation: the TI report, its profile from the certificate. The test CA is no TI CA,
/// so the chain reaches no TI root.
#[test]
fn auto_keeps_a_server_with_a_ti_certificate_with_the_ti() {
    let port = serve("ti-type", None);
    let (code, report) = connect(
        port,
        &["--fqdn", "svc.ti.test", "--env", "ref", "--offline"],
    );
    assert_eq!(code, Some(1), "{report}");
    assert!(report.get("tls_profile").is_none(), "{report}");
    assert_eq!(report["environment"]["name"], "ref");
    assert_eq!(report["profile"]["name"], "fd-tls-s", "{report}");
    assert_eq!(report["valid"], false);
}

/// The conformance check picks the schema by what `pki verify` wrote.
#[test]
fn the_schema_follows_the_output() {
    assert_eq!(
        verify_schema(br#"{"tls_profile": "web"}"#),
        "pki verify tls-server"
    );
    assert_eq!(verify_schema(br#"{"environment": {}}"#), "pki verify");
}

/// Certificates and keys made in the test, ECDSA P-256 throughout: no private key stands in
/// a fixture.
mod made {
    use std::str::FromStr as _;
    use std::time::{Duration, SystemTime};

    use der::Encode as _;
    use der::asn1::Ia5String;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey as _;
    use x509_cert::TbsCertificate;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder as _, CertificateBuilder};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
    use x509_cert::ext::{Extension, ToExtension as _};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
    use x509_cert::time::{Time, Validity};

    /// A key and the name it is certified under.
    pub struct Party {
        pub key: SigningKey,
        pub name: Name,
    }

    impl Party {
        pub fn new(cn: &str) -> Party {
            let key = loop {
                let mut bytes = [0u8; 32];
                getrandom::fill(&mut bytes).unwrap();
                if let Ok(key) = SigningKey::from_slice(&bytes) {
                    break key;
                }
            };
            Party {
                key,
                name: Name::from_str(&format!("CN={cn}")).unwrap(),
            }
        }

        /// The key as PKCS#8 DER, for the server.
        pub fn pkcs8(&self) -> Vec<u8> {
            self.key.to_pkcs8_der().unwrap().as_bytes().to_vec()
        }
    }

    struct Profile {
        issuer: Name,
        subject: Name,
        dns: Option<String>,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            _: SubjectPublicKeyInfoRef<'_>,
            _: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let subject = tbs.subject();
            let ca = self.dns.is_none();
            let mut extensions = vec![
                BasicConstraints {
                    ca,
                    path_len_constraint: None,
                }
                .to_extension(subject, &[])?,
            ];
            if let Some(dns) = &self.dns {
                extensions
                    .push(KeyUsage(KeyUsages::DigitalSignature.into()).to_extension(subject, &[])?);
                let name = GeneralName::DnsName(Ia5String::new(dns).unwrap());
                extensions.push(SubjectAltName(vec![name]).to_extension(subject, &[])?);
            } else {
                extensions.push(
                    KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                        .to_extension(subject, &[])?,
                );
            }
            Ok(extensions)
        }
    }

    /// `subject`'s key certified by `issuer` for `days`, as a CA, or as a server for `dns`.
    pub fn certify(subject: &Party, issuer: &Party, days: u64, dns: Option<&str>) -> Vec<u8> {
        let now = SystemTime::now();
        let validity = Validity::new(
            Time::try_from(now - Duration::from_hours(1)).unwrap(),
            Time::try_from(now + Duration::from_hours(days * 24)).unwrap(),
        );
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).unwrap();
        serial[0] &= 0x7f;
        let profile = Profile {
            issuer: issuer.name.clone(),
            subject: subject.name.clone(),
            dns: dns.map(str::to_owned),
        };
        let spki = SubjectPublicKeyInfoOwned::from_key(subject.key.verifying_key()).unwrap();
        CertificateBuilder::new(profile, SerialNumber::new(&serial).unwrap(), validity, spki)
            .unwrap()
            .build::<_, DerSignature>(&issuer.key)
            .unwrap()
            .to_der()
            .unwrap()
    }
}

/// RFC 5280 6.1: a path ends at its trust anchor. A server sends its leaf, the intermediate,
/// the self-signed root R1, R1's cross-certificate from R2 (same name and key as R1) and the
/// self-signed R2; with R1 the anchor, the verdict's path and the chain view end at R1, and
/// the cross-certificate and R2 are listed apart as sent outside the path, not drawn as R1's
/// issuers.
#[test]
fn rfc_5280_6_1_the_chain_view_ends_at_the_trust_anchor() {
    let leaf = made::Party::new("www.web.test");
    let intermediate = made::Party::new("Intermediate");
    let r1 = made::Party::new("Root R1");
    let r2 = made::Party::new("Root R2");
    let r1_self = made::certify(&r1, &r1, 3650, None);
    let chain = vec![
        CertificateDer::from(made::certify(
            &leaf,
            &intermediate,
            90,
            Some("www.web.test"),
        )),
        CertificateDer::from(made::certify(&intermediate, &r1, 1825, None)),
        CertificateDer::from(r1_self.clone()),
        CertificateDer::from(made::certify(&r1, &r2, 1825, None)),
        CertificateDer::from(made::certify(&r2, &r2, 3650, None)),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.pkcs8()));
    let port = serve_chain(chain, key, None);
    let home = std::env::temp_dir().join(format!("ti-verify-path-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let anchor = home.join("r1.pem");
    let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &r1_self);
    std::fs::write(&anchor, pem.unwrap()).unwrap();
    let target = format!("127.0.0.1:{port}");
    let run = |format: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_ti"))
            .args(["--format", format, "--cacert", anchor.to_str().unwrap()])
            .args(["pki", "verify", "--connect", &target])
            .args(["--validation-profile", "web", "--fqdn", "www.web.test"])
            .env_remove("TI_FORMAT")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env("TI_CACHE_DIR", home.join("cache"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };

    let json = run("json");
    assert_verify_conforms(&json);
    let report: Value = serde_json::from_slice(&json).unwrap();
    let names = |key: &str| -> Vec<(String, String)> {
        report[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let name = c["common_name"].as_str().unwrap().to_owned();
                (name, c["position"].as_str().unwrap().to_owned())
            })
            .collect()
    };
    let at = |name: &str, position: &str| (name.to_owned(), position.to_owned());
    assert_eq!(
        names("path"),
        [
            at("www.web.test", "end_entity"),
            at("Intermediate", "sub_ca"),
            at("Root R1", "trust_anchor"),
        ],
        "{report}"
    );
    assert_eq!(names("chain").len(), 5, "{report}");

    let view = String::from_utf8(run("markdown")).unwrap();
    let (path, outside) = view
        .split_once("Sent, outside the path")
        .unwrap_or_else(|| panic!("no list of the certificates outside the path:\n{view}"));
    let (outside, _) = outside.split_once("-----BEGIN").unwrap_or((outside, ""));
    assert!(path.contains("Root R1"), "{view}");
    assert!(!path.contains("Root R2"), "{view}");
    assert!(
        outside.contains("Root R1 · CA · issued by Root R2"),
        "{view}"
    );
    assert!(outside.contains("Root R2 · CA · self-signed"), "{view}");
    assert!(!outside.contains("Intermediate"), "{view}");
}
