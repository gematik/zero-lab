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

//! [`UreqTransport`]: ti-connector-client's [`Transport`] over blocking ureq with rustls
//! and ring, set up from a `.kon` file the way the Go client does: the TLS trust of
//! [`ti_tls::konnektor`], the client certificate of `pkcs12` credentials (BER and legacy
//! encryption read by ti-pkcs12, no OpenSSL), basic auth in the request.
//!
//! ureq's `TlsConfig` cannot take a certificate verifier, so the TLS layer is a small
//! connector of our own in ureq's connector chain (its `unversioned` API).
//!
//! `send` blocks: the future completes on its first poll. Callers with an async runtime
//! run it on a blocking thread.

use core::fmt;
use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use ti_connector_client::{Dotkon, Error, Method, Request, Response, Transport, TransportError};
use ti_tls::konnektor::{self, Trust};
use ureq::Agent;
use ureq::config::ConfigBuilder;
use ureq::http::header::{
    CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use ureq::typestate::AgentScope;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    TcpConnector, Transport as UreqTransportLayer, TransportAdapter,
};

use crate::net::{self, Net};

pub mod cards;
pub mod documents;
mod probe;
pub(crate) mod session;
pub mod setup;
pub mod store;

pub use probe::{TestOptions, check_config, probe, server_certificate};
pub use session::{Prompt, Session, Wait, card_user, connect, find};

/// Largest response body read; signed and encrypted documents can be large.
const MAX_BODY: u64 = 64 * 1024 * 1024;

/// The HTTP settings of a Konnektor transport: `net`'s connect timeout and user agent, and
/// only an explicit proxy.
///
/// # Errors
///
/// [`net::Error::Setup`] for an unusable proxy.
pub fn agent_config(net: &Net) -> Result<ConfigBuilder<AgentScope>, net::Error> {
    // Only an explicit -x: a Konnektor is in the local network, and a proxy from the
    // environment, which ureq reads by default, would route its traffic (and credentials)
    // elsewhere.
    let mut config = Agent::config_builder()
        .timeout_connect(Some(net.connect_timeout))
        .user_agent(&net.user_agent)
        .proxy(None);
    if let Some(proxy) = net.explicit_proxy() {
        let proxy =
            ureq::Proxy::new(proxy).map_err(|e| net::Error::Setup(format!("proxy: {e}")))?;
        config = config.proxy(Some(proxy));
    }
    Ok(config)
}

/// The Konnektor transport over ureq.
#[derive(Debug)]
pub struct UreqTransport {
    agent: Agent,
}

impl UreqTransport {
    /// The transport for the Konnektor of `dotkon`. `config` carries the caller's
    /// proxy, connect timeout and user agent; TLS comes from `dotkon`, and the timeout
    /// of each request from its [`Request::timeout`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if the credentials or the trust store cannot be used.
    pub fn new(dotkon: &Dotkon, config: ConfigBuilder<AgentScope>) -> Result<Self, Error> {
        let tls = KonnektorTls {
            config: Arc::new(client_config(dotkon, |verifier| verifier, true)?),
            expected_host: dotkon
                .expected_host
                .as_deref()
                .map(|host| {
                    ServerName::try_from(host.to_owned())
                        .map(|_| host.to_owned())
                        .map_err(|e| Error::Config(format!("expectedHost {host:?}: {e}")))
                })
                .transpose()?,
        };
        let connector =
            ().chain(ConnectProxyConnector::default())
                .chain(TcpConnector::default())
                .chain(tls);
        let config = config.http_status_as_error(false).build();
        Ok(UreqTransport {
            agent: Agent::with_parts(config, connector, DefaultResolver::default()),
        })
    }
}

impl Transport for UreqTransport {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        let mut builder = ureq::http::Request::builder()
            .method(match request.method {
                Method::Get => "GET",
                Method::Post => "POST",
            })
            .uri(request.url);
        let headers = [
            ("authorization", request.authorization),
            ("soapaction", request.soap_action),
            (IF_NONE_MATCH.as_str(), request.if_none_match),
            (IF_MODIFIED_SINCE.as_str(), request.if_modified_since),
        ];
        for (name, value) in headers {
            if let Some(value) = value {
                builder = builder.header(name, value);
            }
        }
        if request.soap_action.is_some() {
            builder = builder.header(CONTENT_TYPE, "text/xml; charset=utf-8");
        }
        let http = builder.body(request.body).map_err(|e| failed(&e, false))?;
        let http = self
            .agent
            .configure_request(http)
            .timeout_global(Some(request.timeout))
            .build();
        let mut response = self.agent.run(http).map_err(|e| {
            let timed_out = matches!(e, ureq::Error::Timeout(_));
            failed(&e, timed_out)
        })?;
        let header = |name| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (etag, last_modified, cache_control) =
            (header(ETAG), header(LAST_MODIFIED), header(CACHE_CONTROL));
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| failed(&e, matches!(e, ureq::Error::Timeout(_))))?;
        Ok(Response {
            status,
            body,
            etag,
            last_modified,
            max_age: cache_control.as_deref().and_then(max_age),
        })
    }
}

/// The error with its causes, e.g. "io: connection refused" or the TLS alert.
fn failed(error: &dyn std::error::Error, timed_out: bool) -> TransportError {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !message.contains(&text) {
            message = format!("{message}: {text}");
        }
        source = cause.source();
    }
    TransportError { message, timed_out }
}

fn max_age(cache_control: &str) -> Option<Duration> {
    cache_control
        .split(',')
        .find_map(|d| d.trim().strip_prefix("max-age="))
        .and_then(|secs| secs.parse().ok())
        .map(Duration::from_secs)
}

/// The TLS client config of `dotkon`: [`ti_tls::konnektor`]'s trust, its verifier passed
/// through `wrap`, with the client certificate of `pkcs12` credentials only if
/// `client_auth`.
fn client_config(
    dotkon: &Dotkon,
    wrap: impl FnOnce(Arc<dyn ServerCertVerifier>) -> Arc<dyn ServerCertVerifier>,
    client_auth: bool,
) -> Result<ClientConfig, Error> {
    let trust = Trust::new(
        &dotkon.trust_store,
        dotkon.insecure_skip_verify,
        |provider| {
            Ok(Arc::new(rustls_platform_verifier::Verifier::new(provider)?)
                as Arc<dyn ServerCertVerifier>)
        },
    )
    .map_err(|e| Error::Config(e.0))?;
    let client = if client_auth {
        dotkon
            .credentials
            .client_identity()?
            .map(|(certificate, key)| {
                (
                    CertificateDer::from(certificate),
                    PrivateKeyDer::Pkcs8(with_public_key(&key.pkcs8).into()),
                )
            })
    } else {
        None
    };
    trust
        .client_config_with(wrap, client)
        .map_err(|e| Error::Config(e.0))
}

/// The PKCS#8 key with its public key. ring accepts EC keys only with it, and Java
/// keystores and some card vendors leave it out; P-256 and P-384 keys are re-encoded
/// with it, other keys pass unchanged.
fn with_public_key(pkcs8: &[u8]) -> Vec<u8> {
    use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
    let encoded = if let Ok(key) = p256::SecretKey::from_pkcs8_der(pkcs8) {
        key.to_pkcs8_der().ok()
    } else if let Ok(key) = p384::SecretKey::from_pkcs8_der(pkcs8) {
        key.to_pkcs8_der().ok()
    } else {
        None
    };
    encoded.map_or_else(|| pkcs8.to_vec(), |document| document.as_bytes().to_vec())
}

/// TLS over the chained connection, with our client config and server name.
#[derive(Debug)]
struct KonnektorTls {
    config: Arc<ClientConfig>,
    expected_host: Option<String>,
}

impl<In: UreqTransportLayer> Connector<In> for KonnektorTls {
    type Out = Either<In, TlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let name = konnektor::server_name(
            self.expected_host.as_deref(),
            details.uri.host().unwrap_or_default(),
        )
        .map_err(|_| ureq::Error::Tls("invalid server name"))?;
        let mut conn = ClientConnection::new(self.config.clone(), name)?;
        let mut sock = TransportAdapter::new(transport.boxed());
        sock.set_timeout(details.timeout);
        conn.complete_io(&mut sock)?;
        Ok(Some(Either::B(TlsTransport {
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: StreamOwned { conn, sock },
        })))
    }
}

struct TlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTransport").finish_non_exhaustive()
    }
}

impl UreqTransportLayer for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}
