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

//! The host side of [`crate::check`]: connects to the Konnektor step by step and hands
//! each observation to its check. TCP and TLS are probed directly, so that a refused
//! connection, an untrusted certificate and a refused client tell apart; the service
//! directory and GetCards go through the caller's transport.

use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConnection, DigitallySignedStruct};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use ti_types::Timestamp;

use super::client_config_with;
use crate::check::{
    self, Finding, Report, Status, Step, StepId, TcpFailure, TcpObservation, TlsObservation,
};
use crate::config;
use crate::connector::Connector;
use crate::dotkon::{Credentials, Dotkon};
use crate::error::Error;
use crate::soap::{Timeouts, Transport};

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

/// Checks the `.kon` file `json` step by step, as [`crate::check`] describes. `mode` is
/// the file's Unix permission bits (`None` where there are none), `lookup` expands
/// `${NAME}`, `transport` makes the caller's transport for a valid file.
pub async fn check_config<T: Transport>(
    json: &[u8],
    mode: Option<u32>,
    lookup: impl Fn(&str) -> Option<String>,
    transport: impl FnOnce(&Dotkon) -> Result<T, Error>,
    options: TestOptions,
) -> Report {
    let mut report = Report::default();
    let parsed = Dotkon::parse_with(json, lookup);
    if !report.push(check::file(&parsed, json, mode)) {
        return report.finish();
    }
    let Ok(dotkon) = parsed else {
        return report.finish();
    };
    let client = match &dotkon.credentials {
        Credentials::Pkcs12 { data, password } => Some(config::client_certificate(data, password)),
        Credentials::Basic { .. } | Credentials::None => None,
    };
    let mut tls = None;
    if options.through_proxy {
        let why = "not probed directly: the connection goes through a proxy";
        report.push(Step::skipped(StepId::Tcp, why));
        report.push(Step::skipped(StepId::Tls, why));
    } else {
        let (tcp, observed) = probe(&dotkon, options.connect_timeout);
        if !report.push(check::tcp(&tcp)) {
            return report.finish();
        }
        let Some(observed) = observed else {
            return report.finish();
        };
        if !report.push(check::tls(&dotkon, &observed, options.now)) {
            return report.finish();
        }
        tls = Some(observed);
    }
    let transport = match transport(&dotkon) {
        Ok(transport) => transport,
        Err(e) => {
            let mut step = check::auth(&dotkon, client.as_ref(), tls.as_ref(), None, options.now);
            if step.status != Status::Fail {
                step.findings.push(Finding::new(
                    Status::Fail,
                    e.to_string(),
                    Some("the credentials or the trust store cannot be used"),
                ));
                step = Step::new(StepId::Auth, step.findings);
            }
            report.push(step);
            return report.finish();
        }
    };
    let connected = Connector::connect(&dotkon, transport, options.timeouts).await;
    let directory = connected
        .as_ref()
        .map(|c| c.directory().clone())
        .map_err(Clone::clone);
    let auth = check::auth(
        &dotkon,
        client.as_ref(),
        tls.as_ref(),
        Some(&directory),
        options.now,
    );
    if !report.push(auth) || !report.push(check::sds(&directory)) {
        return report.finish();
    }
    let Ok(connector) = connected else {
        return report.finish();
    };
    let cards = connector.cards().list(&[]).await;
    if report.push(check::context(&dotkon, &cards)) {
        report.push(check::cards(cards.as_deref().unwrap_or_default()));
    }
    report.finish()
}

/// Connects to the Konnektor of `dotkon` and shakes hands with its trust: the TCP
/// observation, and the TLS observation if TCP connected. The handshake offers the
/// client certificate when the credentials can be read, and records the server's
/// certificates also when the handshake fails.
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
    let Some(stream) = stream else {
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
    let config = client_config_with(dotkon, record, true)
        .or_else(|_| client_config_with(dotkon, record, false));
    let failed = |message: String| TlsObservation {
        chain: Vec::new(),
        verified: None,
        handshake: Err(message),
    };
    let config = match config {
        Ok(config) => Arc::new(config),
        Err(e) => return failed(e.to_string()),
    };
    let name = dotkon.expected_host.as_deref().unwrap_or(host).to_owned();
    let name = match ServerName::try_from(name) {
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

/// `(host, port)` of an https URL, the host without IPv6 brackets; port 443 if none.
fn host_port(url: &str) -> Option<(&str, u16)> {
    let (origin, _) = crate::sds::split_origin(url)?;
    let authority = origin.split_once("://")?.1;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let default = if origin.starts_with("https://") {
        443
    } else {
        80
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if after.is_empty() => default,
            None => return None,
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, default)),
    }
    .filter(|(host, _)| !host.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_port_come_from_the_url_with_443_by_default() {
        assert_eq!(
            host_port("https://kon.example:8443/x"),
            Some(("kon.example", 8443))
        );
        assert_eq!(host_port("https://kon.example"), Some(("kon.example", 443)));
        assert_eq!(host_port("https://10.0.0.1:4433"), Some(("10.0.0.1", 4433)));
        assert_eq!(host_port("https://[fe80::1]:8443"), Some(("fe80::1", 8443)));
        assert_eq!(host_port("https://[fe80::1]/"), Some(("fe80::1", 443)));
        assert_eq!(host_port("https://kon.example:x"), None);
        assert_eq!(host_port("ftp://kon.example"), None);
    }
}
