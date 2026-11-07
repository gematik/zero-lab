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

//! The Konnektor's TLS, as the `.kon` file configures it and the Go client verifies it
//! (`VerifyConnection`). A Konnektor is neither a `ti` nor a `web` server: its certificate
//! comes from the operator, so its trust comes from the file.
//!
//! - An end-entity certificate in the trust store is a pin, accepted by equality.
//! - Otherwise the chain must lead to one of its CA certificates and name the server:
//!   `expectedHost` if the file sets it, else the URL's host. That name is also the SNI
//!   ([`server_name`]).
//! - An empty trust store means the operating system's, through the verifier the host
//!   supplies ([`Trust::new`]).
//! - `insecureSkipVerify` accepts any server certificate; the handshake signatures are
//!   still checked.
//!
//! The client certificate of `pkcs12` credentials is the host's to decode and hand to
//! [`Trust::client_config`]. Cipher suites and protocol versions are ring's defaults, not
//! the profiles' of [`crate::client_config`]: Konnektors predate them.

use core::fmt;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore};
use rustls_pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName, UnixTime};

/// Why a `.kon` file's TLS settings cannot be used, naming the setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unusable(pub String);

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unusable {}

/// The verifier of a `.kon` file's trust settings, with the crypto provider it and the
/// client configuration share.
#[derive(Clone)]
pub struct Trust {
    verifier: Arc<dyn ServerCertVerifier>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trust")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl Trust {
    /// The trust of `trust_store` (DER certificates, the `.kon` file's `trustStore`), or
    /// of none with `insecure_skip_verify`. `system` makes the operating system's verifier
    /// over the provider it is given; it is called only for an empty trust store.
    ///
    /// # Errors
    ///
    /// [`Unusable`] for an entry that is no certificate or no usable CA, and when
    /// `system` fails.
    pub fn new(
        trust_store: &[Vec<u8>],
        insecure_skip_verify: bool,
        system: impl FnOnce(Arc<CryptoProvider>) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error>,
    ) -> Result<Trust, Unusable> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if insecure_skip_verify {
            KonnektorVerifier {
                pins: Vec::new(),
                chain: None,
                accept_any: true,
                provider: provider.clone(),
            }
        } else {
            KonnektorVerifier::new(trust_store, provider.clone(), system)?
        };
        Ok(Trust {
            verifier: Arc::new(verifier),
            provider,
        })
    }

    /// The verifier, for a handshake the host runs itself.
    pub fn verifier(&self) -> Arc<dyn ServerCertVerifier> {
        self.verifier.clone()
    }

    /// The client configuration: ring's safe default versions, this trust's verifier, and
    /// `client`'s certificate and key if there are credentials to present.
    ///
    /// # Errors
    ///
    /// [`Unusable`] when the key does not fit the certificate or ring cannot use it.
    pub fn client_config(
        &self,
        client: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    ) -> Result<ClientConfig, Unusable> {
        self.client_config_with(|verifier| verifier, client)
    }

    /// [`Trust::client_config`] with the verifier passed through `wrap`, e.g. to record
    /// what the server presented and what the verifier said.
    ///
    /// # Errors
    ///
    /// As [`Trust::client_config`].
    pub fn client_config_with(
        &self,
        wrap: impl FnOnce(Arc<dyn ServerCertVerifier>) -> Arc<dyn ServerCertVerifier>,
        client: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    ) -> Result<ClientConfig, Unusable> {
        let builder = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Unusable(format!("TLS: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(wrap(self.verifier.clone()));
        match client {
            None => Ok(builder.with_no_client_auth()),
            Some((certificate, key)) => builder
                .with_client_auth_cert(vec![certificate], key)
                .map_err(|e| Unusable(format!("credentials: {e}"))),
        }
    }
}

/// The name the Konnektor's certificate must carry and the handshake sends as SNI:
/// `expected_host` (the `.kon` file's `expectedHost`) if set, else `url_host`, without
/// IPv6 brackets.
///
/// # Errors
///
/// When the chosen name is neither a DNS name nor an IP address.
pub fn server_name(
    expected_host: Option<&str>,
    url_host: &str,
) -> Result<ServerName<'static>, InvalidDnsNameError> {
    let host =
        expected_host.unwrap_or_else(|| url_host.trim_start_matches('[').trim_end_matches(']'));
    ServerName::try_from(host.to_owned())
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
    fn new(
        trust_store: &[Vec<u8>],
        provider: Arc<CryptoProvider>,
        system: impl FnOnce(Arc<CryptoProvider>) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error>,
    ) -> Result<Self, Unusable> {
        let mut pins = Vec::new();
        let mut roots = RootCertStore::empty();
        for (i, der) in trust_store.iter().enumerate() {
            let certificate = ti_pki::Certificate::from_der(der)
                .map_err(|e| Unusable(format!("trustStore[{i}]: {e}")))?;
            if certificate.is_ca() {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|e| Unusable(format!("trustStore[{i}]: {e}")))?;
            } else {
                pins.push(CertificateDer::from(der.clone()));
            }
        }
        let chain: Option<Arc<dyn ServerCertVerifier>> = if !roots.is_empty() {
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| Unusable(format!("trustStore: {e}")))?,
            )
        } else if pins.is_empty() {
            Some(
                system(provider.clone())
                    .map_err(|e| Unusable(format!("system trust store: {e}")))?,
            )
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
