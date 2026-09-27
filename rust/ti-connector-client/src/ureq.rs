//! [`UreqTransport`]: the [`Transport`] over blocking ureq with rustls and ring, set up
//! from a `.kon` file the way the Go client does:
//! - the client certificate of `pkcs12` credentials (BER and legacy encryption read by
//!   ti-pkcs12, no OpenSSL);
//! - server verification against the `.kon` trust store: an end-entity certificate there
//!   is a pin, accepted by equality; otherwise the chain must lead to one of its CA
//!   certificates and name `expectedHost` (or the URL's host), which is also sent as
//!   SNI; an empty trust store means the operating system's;
//! - `insecureSkipVerify` accepts any server certificate (handshake signatures are still
//!   checked).
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

use ::ureq::Agent;
use ::ureq::config::ConfigBuilder;
use ::ureq::http::header::{
    CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use ::ureq::typestate::AgentScope;
use ::ureq::unversioned::resolver::DefaultResolver;
use ::ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    TcpConnector, Transport as UreqTransportLayer, TransportAdapter,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::dotkon::{Credentials, Dotkon};
use crate::error::Error;
use crate::soap::{Method, Request, Response, Transport, TransportError};

/// Largest response body read; signed and encrypted documents can be large.
const MAX_BODY: u64 = 64 * 1024 * 1024;

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
            config: Arc::new(client_config(dotkon)?),
            server_name: dotkon
                .expected_host
                .as_deref()
                .map(|host| {
                    ServerName::try_from(host.to_owned())
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
        let mut builder = ::ureq::http::Request::builder()
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
            let timed_out = matches!(e, ::ureq::Error::Timeout(_));
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
            .map_err(|e| failed(&e, matches!(e, ::ureq::Error::Timeout(_))))?;
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

fn client_config(dotkon: &Dotkon) -> Result<ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = if dotkon.insecure_skip_verify {
        Arc::new(KonnektorVerifier {
            pins: Vec::new(),
            chain: None,
            accept_any: true,
            provider: provider.clone(),
        })
    } else {
        Arc::new(KonnektorVerifier::new(
            &dotkon.trust_store,
            provider.clone(),
        )?)
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    match &dotkon.credentials {
        Credentials::Basic { .. } => Ok(builder.with_no_client_auth()),
        Credentials::Pkcs12 { data, password } => {
            let p12 = ti_pkcs12::decode(data, password)
                .map_err(|e| Error::Config(format!("credentials: {e}")))?;
            let pair = p12.pairs().into_iter().next().ok_or_else(|| {
                Error::Config("credentials: no certificate with its private key".into())
            })?;
            let certificate = CertificateDer::from(p12.certificates[pair.certificate].der.clone());
            let key = PrivateKeyDer::Pkcs8(with_public_key(&p12.keys[pair.key].pkcs8).into());
            builder
                .with_client_auth_cert(vec![certificate], key)
                .map_err(|e| Error::Config(format!("credentials: {e}")))
        }
    }
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

/// Go's `VerifyConnection`: pins by equality, else the chain to the `.kon` CAs (or the
/// operating system's roots when the trust store is empty).
struct KonnektorVerifier {
    pins: Vec<CertificateDer<'static>>,
    chain: Option<Arc<dyn ServerCertVerifier>>,
    accept_any: bool,
    provider: Arc<CryptoProvider>,
}

impl KonnektorVerifier {
    fn new(trust_store: &[Vec<u8>], provider: Arc<CryptoProvider>) -> Result<Self, Error> {
        let mut pins = Vec::new();
        let mut roots = RootCertStore::empty();
        for (i, der) in trust_store.iter().enumerate() {
            let certificate = ti_pki::Certificate::from_der(der)
                .map_err(|e| Error::Config(format!("trustStore[{i}]: {e}")))?;
            if certificate.is_ca() {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|e| Error::Config(format!("trustStore[{i}]: {e}")))?;
            } else {
                pins.push(CertificateDer::from(der.clone()));
            }
        }
        let chain: Option<Arc<dyn ServerCertVerifier>> = if !roots.is_empty() {
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| Error::Config(format!("trustStore: {e}")))?,
            )
        } else if pins.is_empty() {
            Some(Arc::new(
                rustls_platform_verifier::Verifier::new(provider.clone())
                    .map_err(|e| Error::Config(format!("system trust store: {e}")))?,
            ))
        } else {
            None
        };
        Ok(KonnektorVerifier {
            pins,
            chain,
            accept_any: false,
            provider,
        })
    }
}

impl fmt::Debug for KonnektorVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KonnektorVerifier")
            .field("pins", &self.pins.len())
            .field("chain", &self.chain.is_some())
            .field("accept_any", &self.accept_any)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for KonnektorVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.accept_any || self.pins.iter().any(|pin| pin == end_entity) {
            return Ok(ServerCertVerified::assertion());
        }
        match &self.chain {
            Some(chain) => {
                chain.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS over the chained connection, with our client config and server name.
#[derive(Debug)]
struct KonnektorTls {
    config: Arc<ClientConfig>,
    server_name: Option<ServerName<'static>>,
}

impl<In: UreqTransportLayer> Connector<In> for KonnektorTls {
    type Out = Either<In, TlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ::ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let name = if let Some(name) = &self.server_name {
            name.clone()
        } else {
            let host = details.uri.host().unwrap_or_default();
            let host = host.trim_start_matches('[').trim_end_matches(']');
            ServerName::try_from(host.to_owned())
                .map_err(|_| ::ureq::Error::Tls("invalid server name"))?
        };
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

    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: NextTimeout,
    ) -> Result<(), ::ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ::ureq::Error> {
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
