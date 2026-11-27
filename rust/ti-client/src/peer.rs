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

//! The certificate chain a TLS server presents, for a check of its own. The handshake
//! makes no trust decision of its own, ti-pki makes it on the chain afterwards; but the
//! server must prove that it holds the end entity's key, so its handshake signature is
//! verified, with ti-pki's algorithms and so with brainpool keys too.
//!
//! A TLS server's verdict under a TLS profile of `spec/pki-validation` is reached in the
//! handshake instead ([`web_server_verdict`] for `web`), as the transports of that profile
//! reach it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
};
use ti_pki::Timestamp;
use ti_pki::algorithms::{self, brainpool, rsa};
use ti_tls::WebVerifier;
pub use ti_tls::{StatusSource, Verdict};

use crate::error::Error;
use crate::net::{self, Net};
use crate::probe::TlsProfile;
use crate::tls::UreqFetch;

/// TLS 1.3's `ecdsa_brainpoolP256r1tls13_sha256` and its P384 sibling (RFC 8734), which
/// rustls does not know by name.
const BRAINPOOL_P256_TLS13: u16 = 0x081a;
const BRAINPOOL_P384_TLS13: u16 = 0x081b;

/// Signature schemes and the ti-pki algorithms behind them. TLS 1.2's ECDSA schemes name
/// a hash, not a curve, so the brainpool variant of each is a candidate too, and so is
/// the other NIST curve with the same hash, as servers of the Web-PKI sign (a P-384 key
/// with SHA-256). TLS 1.3's schemes bind the curve, and rustls takes the first entry for
/// them. The handshake proves only that the server holds the key; trust in the chain is
/// ti-pki's decision afterwards.
static SCHEMES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        algorithms::ECDSA_P256_SHA256,
        algorithms::ECDSA_P384_SHA384,
        algorithms::ECDSA_P384_SHA256,
        algorithms::ECDSA_P256_SHA384,
        brainpool::ECDSA_BP256R1_SHA256,
        brainpool::ECDSA_BP384R1_SHA384,
        rsa::RSA_PSS_SHA256,
        rsa::RSA_PSS_SHA384,
        rsa::RSA_PSS_SHA512,
        rsa::RSA_PKCS1_SHA256,
        rsa::RSA_PKCS1_SHA384,
        rsa::RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                algorithms::ECDSA_P256_SHA256,
                algorithms::ECDSA_P384_SHA256,
                brainpool::ECDSA_BP256R1_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                algorithms::ECDSA_P384_SHA384,
                algorithms::ECDSA_P256_SHA384,
                brainpool::ECDSA_BP384R1_SHA384,
            ],
        ),
        (SignatureScheme::RSA_PSS_SHA256, &[rsa::RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[rsa::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[rsa::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[rsa::RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[rsa::RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[rsa::RSA_PKCS1_SHA512]),
    ],
};

/// Keeps the chain the server presents and checks only its handshake signature.
#[derive(Debug, Default)]
struct Capture {
    chain: Mutex<Vec<Vec<u8>>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.chain.lock().unwrap_or_else(PoisonError::into_inner) = core::iter::once(end_entity)
            .chain(intermediates)
            .map(|cert| cert.to_vec())
            .collect();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &SCHEMES)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let brainpool = match u16::from(dss.scheme) {
            BRAINPOOL_P256_TLS13 => brainpool::ECDSA_BP256R1_SHA256,
            BRAINPOOL_P384_TLS13 => brainpool::ECDSA_BP384R1_SHA384,
            _ => return rustls::crypto::verify_tls13_signature(message, cert, dss, &SCHEMES),
        };
        let bad = || rustls::Error::InvalidCertificate(CertificateError::BadSignature);
        let cert = ti_pki::Certificate::from_der(cert).map_err(|_| bad())?;
        brainpool
            .verify_signature(cert.public_key(), message, dss.signature())
            .map(|()| HandshakeSignatureValid::assertion())
            .map_err(|_| bad())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes: Vec<SignatureScheme> =
            SCHEMES.mapping.iter().map(|(scheme, _)| *scheme).collect();
        schemes.push(SignatureScheme::Unknown(BRAINPOOL_P256_TLS13));
        schemes.push(SignatureScheme::Unknown(BRAINPOOL_P384_TLS13));
        schemes
    }
}

/// The chain `host` presents on `port`, end entity first, over the proxy `net` names,
/// if any, within `net`'s timeouts.
///
/// # Errors
///
/// [`Error::ServerUnreachable`] when the server cannot be reached, the handshake fails or
/// the server presents no certificate; [`Error::ProxyUnsupported`] when the proxy that
/// applies cannot tunnel.
pub fn server_chain(net: &Net, host: &str, port: u16) -> Result<Vec<Vec<u8>>, Error> {
    let failed = |what: String| Error::ServerUnreachable(format!("{host}:{port}: {what}"));
    let mut socket = open(net, host, port)?;
    let capture = Arc::new(Capture::default());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| failed(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(|e| failed(e.to_string()))?;
    let mut tls =
        ClientConnection::new(Arc::new(config), name).map_err(|e| failed(e.to_string()))?;
    while tls.is_handshaking() {
        tls.complete_io(&mut socket)
            .map_err(|e| failed(format!("TLS handshake failed: {e}")))?;
    }
    tls.send_close_notify();
    // The chain is in hand; a server that drops the connection now changes nothing.
    let _ = tls.complete_io(&mut socket);
    let chain = core::mem::take(&mut *capture.chain.lock().unwrap_or_else(PoisonError::into_inner));
    if chain.is_empty() {
        return Err(failed("the server presented no certificate".into()));
    }
    Ok(chain)
}

/// A connection to `host:port` within `net`'s timeouts, through its proxy if one applies.
fn open(net: &Net, host: &str, port: u16) -> Result<TcpStream, Error> {
    let failed = |what: String| Error::ServerUnreachable(format!("{host}:{port}: {what}"));
    let socket = connect(host, port, net).map_err(|error| match error {
        Connect::Failed(what) => failed(what),
        Connect::ProxyUnsupported(protocol) => Error::ProxyUnsupported {
            server: format!("{host}:{port}"),
            protocol,
        },
    })?;
    socket
        .set_read_timeout(Some(net.max_time))
        .map_err(|e| failed(e.to_string()))?;
    socket
        .set_write_timeout(Some(net.max_time))
        .map_err(|e| failed(e.to_string()))?;
    Ok(socket)
}

/// A TLS server's verdict under a TLS profile of `spec/pki-validation`, reached in a
/// handshake.
#[derive(Clone, Debug)]
pub struct TlsServerVerdict {
    /// `host:port`, as connected to.
    pub server: String,
    /// The TLS profile it was judged under.
    pub profile: TlsProfile,
    /// The name the certificate was checked against, and the one sent as SNI.
    pub name: String,
    /// The instant the server was judged at.
    pub at: Timestamp,
    /// How many roots the check trusted.
    pub roots: usize,
    /// Whether they are the operating system's, not `--cacert`/`--capath`.
    pub system_roots: bool,
    /// The chain the server presented, end entity first, DER.
    pub chain: Vec<Vec<u8>>,
    /// Whether the server stapled an OCSP response.
    pub stapled: bool,
    /// The profile's verdict: its TLSV result code, its warnings and the source of the
    /// revocation status.
    pub verdict: Verdict,
}

/// Connects to `host:port` and judges the server under the `web` TLS profile in the handshake,
/// as the web transports do: the system's roots or `net`'s CA files ([`crate::http::web_check`]),
/// the certificate checked against `name`, sent as SNI, at `at`, its revocation sources asked
/// over plain HTTP. A refusal is a verdict, not an error.
///
/// # Errors
///
/// [`Error::ServerUnreachable`] when the server cannot be reached or the handshake fails for
/// anything but its certificate's verdict (a protocol it does not speak, a handshake
/// signature that does not verify); [`Error::ProxyUnsupported`], and [`Error::Setup`] for an
/// unusable proxy or CA file.
pub fn web_server_verdict(
    net: &Net,
    host: &str,
    port: u16,
    name: &str,
    at: Timestamp,
) -> Result<TlsServerVerdict, Error> {
    let server = format!("{host}:{port}");
    let failed = |what: String| Error::ServerUnreachable(format!("{server}: {what}"));
    let (files, dir) = net.ca_sources();
    let system_roots = files.is_empty() && dir.is_none();
    let check = crate::http::web_check(net)?;
    let roots = check.root_count();
    let judge = Arc::new(Judge {
        web: crate::http::web_verifier_over(net, check)?,
        name: name.to_owned(),
        at,
        seen: Mutex::default(),
    });
    let sni = ServerName::try_from(name.to_owned()).map_err(|e| failed(e.to_string()))?;
    let config = ti_tls::client_config(judge.clone());
    let mut tls =
        ClientConnection::new(Arc::new(config), sni).map_err(|e| failed(e.to_string()))?;
    let mut socket = open(net, host, port)?;
    let mut handshake = Ok(());
    while tls.is_handshaking() && handshake.is_ok() {
        handshake = tls.complete_io(&mut socket).map(|_| ());
    }
    if handshake.is_ok() {
        tls.send_close_notify();
        let _ = tls.complete_io(&mut socket);
    }
    let seen = judge
        .seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let report = |seen: Seen| TlsServerVerdict {
        server: server.clone(),
        profile: TlsProfile::Web,
        name: name.to_owned(),
        at,
        roots,
        system_roots,
        chain: seen.chain,
        stapled: seen.stapled,
        verdict: seen.verdict,
    };
    match (seen, handshake) {
        // Accepted, and the server proved it holds the key.
        (Some(seen), Ok(())) => Ok(report(seen)),
        // Refused by its verdict, which ended the handshake.
        (Some(seen), Err(_)) if !seen.verdict.is_valid() => Ok(report(seen)),
        (_, Err(e)) => Err(failed(format!("TLS handshake failed: {e}"))),
        (None, Ok(())) => Err(failed("the server presented no certificate".into())),
    }
}

/// What the handshake showed the `web` verifier.
struct Seen {
    chain: Vec<Vec<u8>>,
    stapled: bool,
    verdict: Verdict,
}

/// The `web` verifier at a fixed instant, keeping what it saw: rustls reports a refusal as
/// an error, the verdict is wanted whole.
struct Judge {
    web: WebVerifier<UreqFetch>,
    name: String,
    at: Timestamp,
    seen: Mutex<Option<Seen>>,
}

impl core::fmt::Debug for Judge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Judge")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for Judge {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The instant is the caller's (`--at`), not the clock rustls passes.
        let verdict = self.web.verify(
            end_entity,
            intermediates,
            &self.name,
            ocsp_response,
            self.at,
        );
        let accepted = verdict.is_valid();
        let refusal = (!accepted).then(|| verdict.clone());
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(Seen {
            chain: core::iter::once(end_entity)
                .chain(intermediates)
                .map(|cert| cert.to_vec())
                .collect(),
            stapled: !ocsp_response.is_empty(),
            verdict,
        });
        match refusal {
            None => Ok(ServerCertVerified::assertion()),
            Some(verdict) => Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(ti_tls::verifier::Refused(verdict))),
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.web.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.web.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.web.supported_verify_schemes()
    }
}

/// Why [`connect`] failed.
enum Connect {
    Failed(String),
    /// The proxy's protocol.
    ProxyUnsupported(String),
}

impl From<String> for Connect {
    fn from(what: String) -> Self {
        Connect::Failed(what)
    }
}

/// A TCP connection to `host:port`, tunnelled through an HTTP proxy when one applies.
fn connect(host: &str, port: u16, net: &Net) -> Result<TcpStream, Connect> {
    let proxy = net::proxy(net, "https").map_err(|e| format!("HTTP setup: {e}"))?;
    let proxy = proxy.filter(|p| {
        format!("https://{host}:{port}/")
            .parse()
            .is_ok_and(|uri| !p.is_no_proxy(&uri))
    });
    let Some(proxy) = proxy else {
        return Ok(tcp(host, port, net)?);
    };
    if proxy.protocol() != ureq::ProxyProtocol::Http {
        return Err(Connect::ProxyUnsupported(format!("{:?}", proxy.protocol())));
    }
    let mut socket = tcp(proxy.host(), proxy.port(), net)?;
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(user) = proxy.username() {
        use base64ct::Encoding as _;
        use core::fmt::Write as _;
        let credentials = format!("{user}:{}", proxy.password().unwrap_or_default());
        let _ = write!(
            request,
            "Proxy-Authorization: Basic {}\r\n",
            base64ct::Base64::encode_string(credentials.as_bytes())
        );
    }
    request.push_str("\r\n");
    socket
        .write_all(request.as_bytes())
        .map_err(|e| format!("proxy: {e}"))?;
    let mut reader = BufReader::new(socket.try_clone().map_err(|e| e.to_string())?);
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| format!("proxy: {e}"))?;
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("proxy refused the tunnel: {}", status.trim()).into());
    }
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("proxy: {e}"))?;
        if line.trim().is_empty() {
            break;
        }
    }
    // Nothing of the server's may have been read past the proxy's headers yet: the
    // client speaks first in TLS.
    debug_assert!(reader.buffer().is_empty(), "{:?}", reader.buffer());
    let _ = reader.read(&mut []);
    Ok(socket)
}

fn tcp(host: &str, port: u16, net: &Net) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?;
    let mut last = format!("no address for {host}");
    for address in addresses {
        match TcpStream::connect_timeout(&address, net.connect_timeout) {
            Ok(socket) => return Ok(socket),
            Err(e) => last = format!("{address}: {e}"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use p384::ecdsa::signature::hazmat::PrehashSigner as _;
    use pkcs8::DecodePrivateKey as _;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::{CertifiedKey, Signer, SigningKey};
    use rustls::{ServerConfig, ServerConnection, SignatureAlgorithm, SupportedProtocolVersion};
    use sha2::Digest as _;

    use super::*;

    const CA: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/tls/web/ca.pem");
    const P384: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/tls/web/p384.pem");
    const P384_KEY: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/tls/web/p384.key");
    const P256: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/tls/web/p256.pem");
    const P256_KEY: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/tls/web/p256.key");

    /// A key that signs under one scheme whatever its curve, as a TLS 1.2 server may: the
    /// ECDSA schemes of TLS 1.2 name the hash and leave the curve to the certificate
    /// (RFC 8422 section 5.4, RFC 5246 section 7.4.1.4.1).
    #[derive(Debug, Clone, Copy)]
    enum Mixed {
        P384Sha256,
        P256Sha384,
    }

    impl Mixed {
        fn pkcs8(self) -> Vec<u8> {
            let key = match self {
                Self::P384Sha256 => P384_KEY,
                Self::P256Sha384 => P256_KEY,
            };
            match PrivateKeyDer::from_pem_slice(key).unwrap() {
                PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der().to_vec(),
                other => panic!("not PKCS#8: {other:?}"),
            }
        }
    }

    impl SigningKey for Mixed {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&self.scheme())
                .then(|| Box::new(*self) as Box<dyn Signer>)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ECDSA
        }
    }

    impl Signer for Mixed {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            let pkcs8 = self.pkcs8();
            let der = match self {
                Self::P384Sha256 => {
                    let key = p384::ecdsa::SigningKey::from_pkcs8_der(&pkcs8).unwrap();
                    let signature: p384::ecdsa::Signature =
                        key.sign_prehash(&sha2::Sha256::digest(message)).unwrap();
                    signature.to_der().as_bytes().to_vec()
                }
                Self::P256Sha384 => {
                    let key = p256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8).unwrap();
                    let signature: p256::ecdsa::Signature =
                        key.sign_prehash(&sha2::Sha384::digest(message)).unwrap();
                    signature.to_der().as_bytes().to_vec()
                }
            };
            Ok(der)
        }

        fn scheme(&self) -> SignatureScheme {
            match self {
                Self::P384Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
                Self::P256Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            }
        }
    }

    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// A server on a port of its own that completes one handshake under `version`,
    /// signing it with `key`.
    fn serve(key: Mixed, version: &'static SupportedProtocolVersion) -> u16 {
        let leaf = match key {
            Mixed::P384Sha256 => P384,
            Mixed::P256Sha384 => P256,
        };
        let chain = vec![
            CertificateDer::from_pem_slice(leaf).unwrap(),
            CertificateDer::from_pem_slice(CA).unwrap(),
        ];
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(
                    chain,
                    Arc::new(key),
                )))));
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut conn = ServerConnection::new(config).unwrap();
                let _ = conn.complete_io(&mut stream);
                let _ = conn.complete_io(&mut stream);
            }
        });
        port
    }

    fn net() -> Net {
        Net {
            insecure: false,
            cacert: Vec::new(),
            capath: None,
            proxy: Some(String::new()),
            noproxy: None,
            connect_timeout: Duration::from_secs(5),
            max_time: Duration::from_secs(10),
            retry: 0,
            user_agent: "test".into(),
        }
    }

    #[test]
    fn tls12_ecdsa_scheme_names_the_hash_p384_key_signs_sha256() {
        let port = serve(Mixed::P384Sha256, &rustls::version::TLS12);
        let chain = server_chain(&net(), "127.0.0.1", port).unwrap();
        assert_eq!(
            chain[0],
            CertificateDer::from_pem_slice(P384).unwrap().to_vec()
        );
    }

    #[test]
    fn tls12_ecdsa_scheme_names_the_hash_p256_key_signs_sha384() {
        let port = serve(Mixed::P256Sha384, &rustls::version::TLS12);
        let chain = server_chain(&net(), "127.0.0.1", port).unwrap();
        assert_eq!(
            chain[0],
            CertificateDer::from_pem_slice(P256).unwrap().to_vec()
        );
    }

    #[test]
    fn tls13_ecdsa_scheme_binds_the_curve_p384_key_signing_sha256_refused() {
        let port = serve(Mixed::P384Sha256, &rustls::version::TLS13);
        let error = server_chain(&net(), "127.0.0.1", port).unwrap_err();
        assert!(
            matches!(&error, Error::ServerUnreachable(what) if what.contains("UnsupportedSignatureAlgorithmForPublicKeyContext")),
            "{error:?}"
        );
    }
}
