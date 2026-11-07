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

//! `config test`'s driver (`connector::check_config`) against a Konnektor on loopback TLS: the
//! steps from the file to the cards, with the server certificate pinned, changed or
//! accepted insecurely, and with a client certificate required.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64ct::Encoding as _;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use ti_client::connector::{TestOptions, UreqTransport, check_config, server_certificate};
use ti_connector_client::Timeouts;
use ti_connector_client::check::{Report, Status, StepId};
use ti_types::Timestamp;

const CA: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/ca.pem");
const SERVER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server-key.pem");
const OTHER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/other.pem");
const CLIENT_P12: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/client.p12");
const SDS: &[u8] = include_bytes!("../../ti-connector-client/tests/fixtures/ehex-connector.sds");
const GET_CARDS: &[u8] = include_bytes!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/02-GetCards.response-200.xml"
);

const NOW: Timestamp = Timestamp(1_798_761_600);

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}

fn b64(bytes: &[u8]) -> String {
    base64ct::Base64::encode_string(bytes)
}

/// What the fake Konnektor answers to GetCards.
#[derive(Clone, Copy)]
enum Cards {
    Recorded,
    Fault(u32),
}

/// A Konnektor on a loopback port with `server.pem`, answering every connection until
/// the test ends; with `client_ca`, clients must present a certificate under it.
fn konnektor(client_ca: bool, cards: Cards) -> u16 {
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
    let config = Arc::new(
        builder
            .with_single_cert(
                vec![CertificateDer::from(der(SERVER))],
                PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let config = config.clone();
            thread::spawn(move || answer(config, socket, cards));
        }
    });
    port
}

fn answer(config: Arc<ServerConfig>, socket: TcpStream, cards: Cards) -> Option<()> {
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    serve(
        StreamOwned::new(ServerConnection::new(config).ok()?, socket),
        cards,
    )
}

/// The same Konnektor over plain http.
fn konnektor_http(cards: Cards) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            thread::spawn(move || serve(socket, cards));
        }
    });
    port
}

fn serve(stream: impl Read + Write, cards: Cards) -> Option<()> {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let path = line.split(' ').nth(1)?.to_owned();
        let mut length = 0;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).ok()?;
            if header.trim().is_empty() {
                break;
            }
            if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().ok()?;
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        let (status, response) = if path.ends_with("connector.sds") {
            (200, SDS.to_vec())
        } else {
            match cards {
                Cards::Recorded => (200, GET_CARDS.to_vec()),
                Cards::Fault(code) => (500, fault(code).into_bytes()),
            }
        };
        let stream = reader.get_mut();
        write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n",
            response.len()
        )
        .ok()?;
        stream.write_all(&response).ok()?;
        stream.flush().ok()?;
    }
}

fn fault(code: u32) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>Fehler</faultstring><detail><E:Error xmlns:E="http://ws.gematik.de/tel/error/v2.0"><E:Trace><E:Code>{code}</E:Code><E:ErrorText>Fehler</E:ErrorText></E:Trace></E:Error></detail></soap:Fault></soap:Body></soap:Envelope>"#
    )
}

const BASIC: &str = r#"{"type": "basic", "username": "u", "password": "${KON_PASSWORD}"}"#;

fn kon(port: u16, credentials: &str, extra: &str) -> String {
    format!(
        r#"{{"url": "https://127.0.0.1:{port}", "rewriteServiceEndpoints": true,
            "mandantId": "M", "workplaceId": "W", "clientSystemId": "C",
            "credentials": {credentials} {extra}}}"#
    )
}

fn pin(pem: &[u8]) -> String {
    format!(r#", "trustStore": ["{}"]"#, b64(&der(pem)))
}

fn run(json: &str) -> Report {
    let options = TestOptions {
        connect_timeout: Duration::from_secs(2),
        timeouts: Timeouts {
            short: Duration::from_secs(5),
            long: Duration::from_secs(5),
        },
        now: NOW,
        through_proxy: false,
    };
    check_config(
        json.as_bytes(),
        Some(0o600),
        |name| (name == "KON_PASSWORD").then(|| "p".to_owned()),
        |dotkon| UreqTransport::new(dotkon, ureq::Agent::config_builder()),
        options,
    )
}

fn status(report: &Report, id: StepId) -> Status {
    report.steps.iter().find(|s| s.id == id).unwrap().status
}

fn dump(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap()
}

#[test]
fn a_pinned_konnektor_passes_every_step() {
    let port = konnektor(false, Cards::Recorded);
    let report = run(&kon(port, BASIC, &pin(SERVER)));
    assert_eq!(report.status, Status::Ok, "{}", dump(&report));
    assert!(dump(&report).contains("matches the pinned certificate"));
}

#[test]
fn a_changed_server_certificate_fails_the_tls_step() {
    let port = konnektor(false, Cards::Recorded);
    let report = run(&kon(port, BASIC, &pin(OTHER)));
    assert_eq!(
        status(&report, StepId::Tls),
        Status::Fail,
        "{}",
        dump(&report)
    );
    assert_eq!(status(&report, StepId::Auth), Status::Skip);
}

#[test]
fn insecure_skip_verify_is_a_warning_outside_production() {
    let port = konnektor(false, Cards::Recorded);
    let report = run(&kon(port, BASIC, r#", "insecureSkipVerify": true"#));
    assert_eq!(report.status, Status::Warn, "{}", dump(&report));
    assert_eq!(status(&report, StepId::Cards), Status::Ok);
}

#[test]
fn a_konnektor_that_requires_a_client_certificate_refuses_basic() {
    let port = konnektor(true, Cards::Recorded);
    let report = run(&kon(port, BASIC, &pin(SERVER)));
    assert_eq!(
        status(&report, StepId::Tls),
        Status::Ok,
        "{}",
        dump(&report)
    );
    assert_eq!(
        status(&report, StepId::Auth),
        Status::Fail,
        "{}",
        dump(&report)
    );
}

#[test]
fn mutual_tls_with_the_pkcs12_client_certificate_passes() {
    let port = konnektor(true, Cards::Recorded);
    let credentials = format!(
        r#"{{"type": "pkcs12", "data": "{}", "password": "${{KON_PASSWORD}}"}}"#,
        b64(CLIENT_P12)
    )
    .replace("${KON_PASSWORD}", "00");
    let report = run(&kon(port, &credentials, &pin(SERVER)));
    assert_eq!(
        status(&report, StepId::Auth),
        Status::Ok,
        "{}",
        dump(&report)
    );
    assert_eq!(
        status(&report, StepId::Cards),
        Status::Ok,
        "{}",
        dump(&report)
    );
}

#[test]
fn a_refused_call_context_fails_the_context_step() {
    let port = konnektor(false, Cards::Fault(4021));
    let report = run(&kon(port, BASIC, &pin(SERVER)));
    assert_eq!(
        status(&report, StepId::Context),
        Status::Fail,
        "{}",
        dump(&report)
    );
    assert!(dump(&report).contains("workplaceId"));
    assert_eq!(status(&report, StepId::Cards), Status::Skip);
}

#[test]
fn a_closed_port_fails_the_tcp_step() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let report = run(&kon(port, BASIC, &pin(SERVER)));
    assert_eq!(
        status(&report, StepId::Tcp),
        Status::Fail,
        "{}",
        dump(&report)
    );
    assert!(dump(&report).contains("connection refused"));
}

/// The pin a user confirms is what the server presents, fetched without trusting it,
/// also from a Konnektor that requires a client certificate.
#[test]
fn the_server_certificate_is_fetched_without_trusting_it() {
    let port = konnektor(true, Cards::Recorded);
    let chain = server_certificate(
        &format!("https://127.0.0.1:{port}"),
        None,
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(chain[0], der(SERVER));
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let error = server_certificate(
        &format!("https://127.0.0.1:{closed}"),
        None,
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(error.contains("connection refused"), "{error}");
    let port = konnektor_http(Cards::Recorded);
    let error = server_certificate(
        &format!("http://127.0.0.1:{port}"),
        None,
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(error.contains("http"), "{error}");
}
