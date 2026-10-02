//! `pki verify --connect`: the certificate chain a TLS server presents. The handshake
//! makes no trust decision of its own, ti-pki makes it on the chain afterwards; but the
//! server must prove that it holds the end entity's key, so its handshake signature is
//! verified, with ti-pki's algorithms and so with brainpool keys too.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
};
use ti_pki::algorithms::{self, brainpool, rsa};

use crate::error::CliError;
use crate::net::NetArgs;

/// TLS 1.3's `ecdsa_brainpoolP256r1tls13_sha256` and its P384 sibling (RFC 8734), which
/// rustls does not know by name.
const BRAINPOOL_P256_TLS13: u16 = 0x081a;
const BRAINPOOL_P384_TLS13: u16 = 0x081b;

/// Signature schemes and the ti-pki algorithms behind them. TLS 1.2's ECDSA schemes name
/// a hash, not a curve, so the brainpool variant of each is a candidate too.
static SCHEMES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        algorithms::ECDSA_P256_SHA256,
        algorithms::ECDSA_P384_SHA384,
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
                brainpool::ECDSA_BP256R1_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                algorithms::ECDSA_P384_SHA384,
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

/// `HOST[:PORT]`, the port 443 by default; IPv6 addresses in brackets.
pub fn target(value: &str) -> Result<(String, u16), String> {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port))
            if !host.ends_with(':') && (!host.contains(':') || host.ends_with(']')) =>
        {
            let port = port
                .parse()
                .map_err(|_| format!("{port:?} is not a port"))?;
            (host, port)
        }
        _ => (value, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok((host.to_owned(), port))
}

/// The chain `host` presents on `port`, end entity first, over the proxy `net` names,
/// if any, within `net`'s timeouts.
pub fn server_chain(host: &str, port: u16, net: &NetArgs) -> Result<Vec<Vec<u8>>, CliError> {
    let failed = |what: String| CliError::ServerUnreachable(format!("{host}:{port}: {what}"));
    let mut socket = connect(host, port, net).map_err(failed)?;
    socket
        .set_read_timeout(Some(net.max_time))
        .map_err(|e| failed(e.to_string()))?;
    socket
        .set_write_timeout(Some(net.max_time))
        .map_err(|e| failed(e.to_string()))?;

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

/// A TCP connection to `host:port`, tunnelled through an HTTP proxy when one applies.
fn connect(host: &str, port: u16, net: &NetArgs) -> Result<TcpStream, String> {
    let proxy = crate::http::proxy(net, "https").map_err(|e| e.to_string())?;
    let proxy = proxy.filter(|p| {
        format!("https://{host}:{port}/")
            .parse()
            .is_ok_and(|uri| !p.is_no_proxy(&uri))
    });
    let Some(proxy) = proxy else {
        return tcp(host, port, net);
    };
    if proxy.protocol() != ureq::ProxyProtocol::Http {
        return Err(format!(
            "--connect goes through HTTP proxies only, not {:?}",
            proxy.protocol()
        ));
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
        return Err(format!("proxy refused the tunnel: {}", status.trim()));
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
    debug_assert!(reader.buffer().is_empty());
    let _ = reader.read(&mut []);
    Ok(socket)
}

fn tcp(host: &str, port: u16, net: &NetArgs) -> Result<TcpStream, String> {
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
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            target("epa-as-1.ref.epa4all.de"),
            Ok(("epa-as-1.ref.epa4all.de".into(), 443))
        );
        assert_eq!(target("host:8443"), Ok(("host".into(), 8443)));
        assert_eq!(target("[::1]:8443"), Ok(("::1".into(), 8443)));
        assert_eq!(target("[::1]"), Ok(("::1".into(), 443)));
        assert!(target("host:http").is_err());
        assert!(target(":443").is_err());
    }
}
