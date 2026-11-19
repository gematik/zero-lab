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

//! The sidecar's own TLS on a TCP listener inside the cluster (servers.md rule 29): its
//! certificate and key, and for mTLS a client CA and an allowlist of client identities, all
//! read once at start and checked as rule 17 asks.
//!
//! The handshake does not demand a client certificate, so that `grpc.health.v1` answers a
//! probe that has none (rule 31); the gRPC transport holds every call of the HSM proxy
//! interface to the allowlist.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use der::Decode as _;
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

/// TLS 1.3 and 1.2, nothing older (spec/pki-validation TLSV-010).
static VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// ring with the AES-GCM suites with ECDHE and the P-256 and P-384 groups of
/// spec/pki-validation (TLSV-010 to 012): the profile ti-tls has for clients, constants here
/// so that the sidecar does not carry the PKI stack; a test holds the two equal.
#[must_use]
pub fn provider() -> CryptoProvider {
    use rustls::CipherSuite as S;
    use rustls::NamedGroup as G;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            S::TLS13_AES_128_GCM_SHA256
                | S::TLS13_AES_256_GCM_SHA384
                | S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | S::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
    });
    provider
        .kx_groups
        .retain(|group| matches!(group.name(), G::secp256r1 | G::secp384r1));
    provider
}

/// How long a client has for its handshake before the connection is dropped (rule 24).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the TLS material does not start the sidecar; names what is wrong, never key material.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TlsError(String);

fn error(message: impl Into<String>) -> TlsError {
    TlsError(message.into())
}

/// The TLS of a listener: the server's certificate chain and key, and for mTLS the client
/// CA and the identities admitted.
pub struct TlsListener {
    config: Arc<ServerConfig>,
    allow: Option<Vec<String>>,
}

/// The client CA bundle and the identities, DNS names or URIs such as SPIFFE IDs, that a
/// client certificate must name one of.
pub struct Clients<'a> {
    /// The CA bundle, PEM.
    pub ca: &'a [u8],
    /// The identities admitted, at least one.
    pub allow: Vec<String>,
}

impl TlsListener {
    /// Checks the material as rule 17 asks and builds the listener's TLS: a certificate
    /// chain and a key that match, a certificate valid at `now`, and, with `clients`, a CA
    /// bundle that is not empty and an allowlist that is not empty.
    ///
    /// # Errors
    ///
    /// [`TlsError`] naming what does not hold.
    pub fn new(
        chain: &[u8],
        key: &[u8],
        clients: Option<Clients<'_>>,
        now: SystemTime,
    ) -> Result<TlsListener, TlsError> {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
            .collect::<Result<_, _>>()
            .map_err(|_| error("the certificate file is not PEM certificates"))?;
        let leaf = chain
            .first()
            .ok_or_else(|| error("the certificate file holds no certificate"))?;
        let certificate = x509_cert::Certificate::from_der(leaf.as_ref())
            .map_err(|_| error("the certificate does not parse"))?;
        let validity = certificate.tbs_certificate().validity();
        if now < validity.not_before.to_system_time() {
            return Err(error("the certificate is not valid yet"));
        }
        if now > validity.not_after.to_system_time() {
            return Err(error("the certificate has expired"));
        }
        let key = PrivateKeyDer::from_pem_slice(key)
            .map_err(|_| error("the key file is not a PEM private key"))?;
        let provider = Arc::new(provider());
        // from_der also holds the key to the certificate's public key.
        rustls::sign::CertifiedKey::from_der(chain.clone(), key.clone_key(), &provider).map_err(
            |e| match e {
                rustls::Error::InconsistentKeys(_) => {
                    error("the key does not match the certificate")
                }
                _ => error("the key is not one the profile takes"),
            },
        )?;
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(VERSIONS)
            .map_err(|_| error("the profile's protocol versions"))?;
        let (builder, allow) = match clients {
            None => (builder.with_no_client_auth(), None),
            Some(clients) => {
                if clients.allow.is_empty() {
                    return Err(error("mTLS without an allowlist of client identities"));
                }
                let mut roots = RootCertStore::empty();
                for ca in CertificateDer::pem_slice_iter(clients.ca) {
                    let ca = ca.map_err(|_| error("the CA file is not PEM certificates"))?;
                    roots
                        .add(ca)
                        .map_err(|_| error("a certificate of the CA file is not a CA"))?;
                }
                if roots.is_empty() {
                    return Err(error("the CA file holds no certificate"));
                }
                let verifier = WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::clone(&provider),
                )
                .allow_unauthenticated()
                .build()
                .map_err(|_| error("the client CA bundle"))?;
                (
                    builder.with_client_cert_verifier(verifier),
                    Some(clients.allow),
                )
            }
        };
        let mut config = builder
            .with_single_cert(chain, key)
            .map_err(|_| error("the certificate and key"))?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(TlsListener {
            config: Arc::new(config),
            allow,
        })
    }

    /// Whether this listener asks for client certificates (mTLS).
    #[must_use]
    pub fn is_mutual(&self) -> bool {
        self.allow.is_some()
    }

    /// Whether a call over a connection whose client named `peer` may use the interface:
    /// always without mTLS, and with it only for a client certificate that names an
    /// identity of the allowlist.
    pub(crate) fn admits(&self, peer: Option<&Peer>) -> bool {
        match &self.allow {
            None => true,
            Some(allow) => {
                peer.is_some_and(|peer| peer.names.iter().any(|name| allow.contains(name)))
            }
        }
    }

    /// The connections of `listener`, each after its handshake. A handshake that fails or
    /// takes longer than [`HANDSHAKE_TIMEOUT`] drops that connection and no other.
    pub(crate) fn incoming(
        &self,
        listener: TcpListener,
    ) -> tokio_stream::wrappers::ReceiverStream<io::Result<Connection>> {
        let acceptor = TlsAcceptor::from(Arc::clone(&self.config));
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        if sender.send(Err(e)).await.is_err() {
                            return;
                        }
                        continue;
                    }
                };
                let (acceptor, sender) = (acceptor.clone(), sender.clone());
                tokio::spawn(async move {
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = sender.send(Ok(Connection::new(stream))).await;
                    }
                });
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(receiver)
    }
}

/// What a client certificate names: its DNS names and URIs (a SPIFFE ID among them). The
/// chain was verified against the client CA in the handshake.
#[derive(Clone, Debug, Default)]
pub(crate) struct Peer {
    names: Vec<String>,
}

impl Peer {
    fn of(stream: &TlsStream<TcpStream>) -> Option<Peer> {
        let leaf = stream.get_ref().1.peer_certificates()?.first()?;
        let certificate = x509_cert::Certificate::from_der(leaf.as_ref()).ok()?;
        let (_, alt) = certificate
            .tbs_certificate()
            .get_extension::<SubjectAltName>()
            .ok()??;
        let names = alt
            .0
            .into_iter()
            .filter_map(|name| match name {
                GeneralName::DnsName(name) => Some(name.to_string()),
                GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect();
        Some(Peer { names })
    }
}

/// A TLS connection after its handshake, with what its client certificate named.
pub(crate) struct Connection {
    stream: TlsStream<TcpStream>,
    peer: Option<Peer>,
}

impl Connection {
    fn new(stream: TlsStream<TcpStream>) -> Connection {
        let peer = Peer::of(&stream);
        Connection { stream, peer }
    }
}

impl Connection {
    /// What the client certificate named, if the client presented one.
    pub(crate) fn peer(&self) -> Option<&Peer> {
        self.peer.as_ref()
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
