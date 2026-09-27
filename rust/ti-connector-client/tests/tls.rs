//! The ureq transport against a loopback TLS server, with OpenSSL-generated
//! certificates (`tests/tls/generate.sh`): trust store as CA or pin, `expectedHost`
//! as name and SNI, insecure mode, mutual TLS from PKCS#12 credentials, timeouts.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;
use futures_lite::future::block_on;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use ti_connector_client::ureq::UreqTransport;
use ti_connector_client::{Dotkon, Method, Request, Transport, TransportError};

const CA: &[u8] = include_bytes!("tls/ca.pem");
const SERVER: &[u8] = include_bytes!("tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("tls/server-key.pem");
const OTHER: &[u8] = include_bytes!("tls/other.pem");
const CLIENT_P12: &[u8] = include_bytes!("tls/client.p12");
const CLIENT_NOPUB_P12: &[u8] = include_bytes!("tls/client-nopub.p12");

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// What the server saw of the one request it answered.
struct Seen {
    sni: Option<String>,
    head: String,
}

/// Serves one request on a loopback port with `server.pem`, answering `200 OK`; with
/// `client_ca`, the client must present a certificate under it. `stall` never answers.
fn serve(client_ca: bool, stall: bool) -> (u16, JoinHandle<Option<Seen>>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if client_ca {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der(CA))).unwrap();
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let config = builder
        .with_single_cert(
            vec![CertificateDer::from(der(SERVER))],
            PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().ok()?;
        socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).ok()?, socket);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).ok()? == 0 {
                return None;
            }
            head.push(byte[0]);
        }
        let sni = tls.conn.server_name().map(str::to_owned);
        if stall {
            thread::sleep(Duration::from_secs(2));
        } else {
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: \"e1\"\r\nConnection: close\r\n\r\nok")
                .ok()?;
            tls.conn.send_close_notify();
            tls.flush().ok()?;
        }
        Some(Seen {
            sni,
            head: String::from_utf8(head).ok()?,
        })
    });
    (port, handle)
}

fn dotkon(port: u16, extra: &str, credentials: &str) -> Dotkon {
    let json = format!(
        r#"{{"url": "https://127.0.0.1:{port}", "mandantId": "M", "workplaceId": "W",
            "clientSystemId": "C", "credentials": {credentials} {extra}}}"#
    );
    Dotkon::parse_with(json.as_bytes(), |_| None).unwrap()
}

const BASIC: &str = r#"{"type": "basic", "username": "u", "password": "p"}"#;

fn get(
    dotkon: &Dotkon,
    timeout: Duration,
) -> Result<ti_connector_client::Response, TransportError> {
    let transport = UreqTransport::new(dotkon, ureq::Agent::config_builder()).unwrap();
    let url = format!("{}/connector.sds", dotkon.url);
    block_on(transport.send(&Request {
        method: Method::Get,
        url: &url,
        soap_action: None,
        authorization: dotkon.authorization().as_deref().map(|_| "Basic dTpw"),
        if_none_match: None,
        if_modified_since: None,
        body: &[],
        timeout,
        operation: None,
    }))
}

const SECOND: Duration = Duration::from_secs(1);

#[test]
fn ca_trust_store_with_expected_host() {
    let (port, server) = serve(false, false);
    let kon = dotkon(
        port,
        &format!(
            r#", "trustStore": ["{}"], "expectedHost": "konnektor.test""#,
            b64(&der(CA))
        ),
        BASIC,
    );
    let response = get(&kon, 5 * SECOND).unwrap();
    assert_eq!(
        (
            response.status,
            response.body.as_slice(),
            response.etag.as_deref()
        ),
        (200, &b"ok"[..], Some("\"e1\""))
    );
    let seen = server.join().unwrap().unwrap();
    assert_eq!(
        seen.sni.as_deref(),
        Some("konnektor.test"),
        "expectedHost is the SNI"
    );
    assert!(
        seen.head.contains("authorization: Basic dTpw"),
        "{}",
        seen.head
    );
}

#[test]
fn ca_trust_store_checks_the_name() {
    let (port, _server) = serve(false, false);
    let kon = dotkon(
        port,
        &format!(r#", "trustStore": ["{}"]"#, b64(&der(CA))),
        BASIC,
    );
    let error = get(&kon, 5 * SECOND).unwrap_err();
    assert!(
        error.message.contains("not valid for name \"127.0.0.1\""),
        "{}",
        error.message
    );
}

#[test]
fn a_pinned_certificate_is_trusted_by_equality() {
    let (port, server) = serve(false, false);
    let kon = dotkon(
        port,
        &format!(r#", "trustStore": ["{}"]"#, b64(&der(SERVER))),
        BASIC,
    );
    assert_eq!(get(&kon, 5 * SECOND).unwrap().status, 200);
    assert_eq!(
        server.join().unwrap().unwrap().sni,
        None,
        "no SNI for an IP address"
    );

    let (port, _server) = serve(false, false);
    let kon = dotkon(
        port,
        &format!(r#", "trustStore": ["{}"]"#, b64(&der(OTHER))),
        BASIC,
    );
    let error = get(&kon, 5 * SECOND).unwrap_err();
    assert!(error.message.contains("UnknownIssuer"), "{}", error.message);
}

#[test]
fn insecure_skip_verify_accepts_any_certificate() {
    let (port, _server) = serve(false, false);
    let kon = dotkon(port, r#", "insecureSkipVerify": true"#, BASIC);
    assert_eq!(get(&kon, 5 * SECOND).unwrap().status, 200);
}

#[test]
fn mutual_tls_from_pkcs12_credentials() {
    let credentials = format!(
        r#"{{"type": "pkcs12", "data": "{}", "password": "00"}}"#,
        b64(CLIENT_P12)
    );
    let pinned = format!(r#", "trustStore": ["{}"]"#, b64(&der(SERVER)));

    let (port, server) = serve(true, false);
    assert_eq!(
        get(&dotkon(port, &pinned, &credentials), 5 * SECOND)
            .unwrap()
            .status,
        200
    );
    let seen = server.join().unwrap().unwrap();
    assert!(!seen.head.contains("authorization"), "{}", seen.head);

    let (port, server) = serve(true, false);
    assert!(
        get(&dotkon(port, &pinned, BASIC), 5 * SECOND).is_err(),
        "no client certificate"
    );
    assert!(server.join().unwrap().is_none());
}

#[test]
fn the_request_timeout_is_enforced() {
    let (port, _server) = serve(false, true);
    let kon = dotkon(port, r#", "insecureSkipVerify": true"#, BASIC);
    let error = get(&kon, Duration::from_millis(300)).unwrap_err();
    assert!(error.timed_out, "{}", error.message);
}

#[test]
fn unusable_credentials_are_a_configuration_error() {
    let credentials = format!(
        r#"{{"type": "pkcs12", "data": "{}", "password": "wrong"}}"#,
        b64(CLIENT_P12)
    );
    let kon = dotkon(1, "", &credentials);
    let error = UreqTransport::new(&kon, ureq::Agent::config_builder()).unwrap_err();
    assert!(
        matches!(error, ti_connector_client::Error::Config(_)),
        "{error}"
    );
}

#[test]
fn client_keys_without_their_public_key_work() {
    let credentials = format!(
        r#"{{"type": "pkcs12", "data": "{}", "password": "00"}}"#,
        b64(CLIENT_NOPUB_P12)
    );
    let pinned = format!(r#", "trustStore": ["{}"]"#, b64(&der(SERVER)));
    let (port, server) = serve(true, false);
    assert_eq!(
        get(&dotkon(port, &pinned, &credentials), 5 * SECOND)
            .unwrap()
            .status,
        200
    );
    assert!(server.join().unwrap().is_some());
}
