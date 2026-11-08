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

//! The host side of [`ti_connector_client::check`]: connects to the Konnektor step by step
//! and hands each observation to its check. TCP and TLS are probed directly, so that a
//! refused connection, an untrusted certificate and a refused client tell apart; the
//! service directory and GetCards go through the caller's transport.

use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConnection, DigitallySignedStruct};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use ti_connector_client::check::{
    self, Report, TcpFailure, TcpObservation, TlsObservation, host_port,
};
use ti_connector_client::{Credentials, Dotkon, Error, Timeouts, Transport};
use ti_tls::konnektor;
use ti_types::Timestamp;

use super::client_config;
use crate::block_on;

/// How [`check_config`] runs.
#[derive(Clone, Copy, Debug)]
pub struct TestOptions {
    /// For the TCP connection and the TLS handshake of the probe.
    pub connect_timeout: Duration,
    /// For the service directory and GetCards.
    pub timeouts: Timeouts,
    /// The time certificates are judged at.
    pub now: Timestamp,
    /// The caller's transport goes through a proxy: TCP and TLS are not probed
    /// directly, since the Konnektor may be reachable only through it.
    pub through_proxy: bool,
}

/// Checks the `.kon` file `json` step by step with [`check::run`], probing TCP and TLS
/// with [`probe`]. `mode` is the file's Unix permission bits (`None` where there are
/// none), `lookup` expands `${NAME}`, `transport` makes the caller's transport for a
/// valid file.
pub fn check_config<T: Transport>(
    json: &[u8],
    mode: Option<u32>,
    lookup: impl Fn(&str) -> Option<String>,
    transport: impl FnOnce(&Dotkon) -> Result<T, Error>,
    options: TestOptions,
) -> Report {
    let probe = (!options.through_proxy)
        .then_some(|dotkon: &Dotkon| probe(dotkon, options.connect_timeout));
    block_on(check::run(
        json,
        mode,
        lookup,
        probe,
        transport,
        check::Options {
            timeouts: options.timeouts,
            now: options.now,
        },
    ))
}

/// The certificates the Konnektor at `url` presents, its own first, trusting none of
/// them: what a user confirms as the pin. `expected_host` is the name sent as SNI.
///
/// # Errors
///
/// Why no certificate came: no connection, an http url, a failed handshake.
pub fn server_certificate(
    url: &str,
    expected_host: Option<&str>,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    let dotkon = Dotkon {
        version: None,
        url: url.to_owned(),
        rewrite_service_endpoints: false,
        mandant_id: String::new(),
        workplace_id: String::new(),
        client_system_id: String::new(),
        user_id: None,
        credentials: Credentials::None,
        env: None,
        insecure_skip_verify: true,
        expected_host: expected_host.map(str::to_owned),
        trust_store: Vec::new(),
        variables: Vec::new(),
    };
    let (tcp, tls) = probe(&dotkon, timeout);
    if tcp.result.is_err() {
        let step = check::tcp(&tcp);
        return Err(step.findings[0].message.clone());
    }
    let tls = tls.ok_or_else(|| format!("{url} is http: it has no certificate"))?;
    if tls.chain.is_empty() {
        return Err(format!(
            "no server certificate: {}",
            tls.handshake.err().unwrap_or_default()
        ));
    }
    Ok(tls.chain)
}

/// Connects to the Konnektor of `dotkon` and shakes hands with its trust: the TCP
/// observation, and the TLS observation if TCP connected and the url is https. The
/// handshake offers the client certificate when the credentials can be read, and records
/// the server's certificates also when the handshake fails.
pub fn probe(dotkon: &Dotkon, timeout: Duration) -> (TcpObservation, Option<TlsObservation>) {
    let Some((host, port)) = host_port(&dotkon.url) else {
        let observation = TcpObservation {
            target: dotkon.url.clone(),
            result: Err(TcpFailure::Other("url has no host".into())),
        };
        return (observation, None);
    };
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let (stream, tcp) = connect(host, port, timeout);
    let observation = TcpObservation {
        target,
        result: tcp,
    };
    let Some(stream) = stream.filter(|_| check::is_https(dotkon)) else {
        return (observation, None);
    };
    (observation, Some(handshake(dotkon, host, stream, timeout)))
}

fn connect(
    host: &str,
    port: u16,
    timeout: Duration,
) -> (Option<TcpStream>, Result<String, TcpFailure>) {
    let addresses: Vec<_> = match (host, port).to_socket_addrs() {
        Ok(addresses) => addresses.collect(),
        Err(e) => return (None, Err(TcpFailure::Resolve(e.to_string()))),
    };
    let mut failure = TcpFailure::Resolve("no address".into());
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return (Some(stream), Ok(address.to_string())),
            Err(e) => {
                failure = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => TcpFailure::Refused(e.to_string()),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                        TcpFailure::Timeout(e.to_string())
                    }
                    _ => TcpFailure::Other(e.to_string()),
                };
            }
        }
    }
    (None, Err(failure))
}

fn handshake(
    dotkon: &Dotkon,
    host: &str,
    mut stream: TcpStream,
    timeout: Duration,
) -> TlsObservation {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = |inner| -> Arc<dyn ServerCertVerifier> {
        Arc::new(Recording {
            inner,
            seen: seen.clone(),
        })
    };
    // Without usable credentials, still look at the server; the auth step says why
    // the credentials cannot be used.
    let config =
        client_config(dotkon, record, true).or_else(|_| client_config(dotkon, record, false));
    let failed = |message: String| TlsObservation {
        chain: Vec::new(),
        verified: None,
        handshake: Err(message),
    };
    let config = match config {
        Ok(config) => Arc::new(config),
        Err(e) => return failed(e.to_string()),
    };
    let name = match konnektor::server_name(dotkon.expected_host.as_deref(), host) {
        Ok(name) => name,
        Err(e) => return failed(format!("server name: {e}")),
    };
    let result = ClientConnection::new(config, name)
        .map_err(|e| e.to_string())
        .and_then(|mut conn| {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            conn.complete_io(&mut stream).map_err(|e| e.to_string())?;
            Ok(())
        });
    let seen = std::mem::take(&mut *seen.lock().unwrap_or_else(PoisonError::into_inner));
    TlsObservation {
        chain: seen.chain,
        verified: seen.verified,
        handshake: result,
    }
}

#[derive(Debug, Default)]
struct Seen {
    chain: Vec<Vec<u8>>,
    verified: Option<Result<(), String>>,
}

/// The `.kon` verifier, recording what the server sent and what the verifier said.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ServerCertVerifier>,
    seen: Arc<Mutex<Seen>>,
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.chain = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|c| c.to_vec())
            .collect();
        seen.verified = Some(result.as_ref().map(|_| ()).map_err(ToString::to_string));
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
