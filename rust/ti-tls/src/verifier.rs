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

//! The two profiles as rustls verifiers, and the client configuration that offers only what
//! `spec/pki-validation` allows (TLSV-010 to 013).
//!
//! A verifier is immutable over one snapshot of trust material: when the material is
//! refreshed, the host builds a new verifier and configuration and swaps its `Arc`, so a
//! handshake reads no shared state but the verdict cache, and a cached verdict never outlives
//! its material (TLSV-050).

use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, OtherError, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use ti_pki::revocation::RevocationChecker;
use ti_pki::tls::ServerCheck;
use ti_pki::{Certificate, Timestamp};

use crate::algorithms::{BRAINPOOL_P256_TLS13, BRAINPOOL_P384_TLS13, TI_SCHEMES, WEB_SCHEMES};
use crate::fetch::Fetch;
use crate::verdict::{Code, Verdict};
use crate::web::WebCheck;

/// OCSP-005: how long a TI responder's answer is reused (TLSV-051).
const TI_STATUS_REUSE: Duration = Duration::from_hours(1);

/// TLSV-010: TLS 1.3 and 1.2, nothing older.
pub static VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// A client configuration for one profile's verifier: TLS 1.3 and 1.2 only, AES-GCM suites
/// with ECDHE, P-256 and P-384 key exchange (TLSV-010 to 012), on ring.
///
/// # Panics
///
/// Never: the versions are among those the provider supports.
pub fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(VERSIONS)
        .expect("ring supports TLS 1.3 and 1.2")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// ring with the cipher suites and groups the profiles allow.
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

/// Accepted verdicts by chain, host and profile, until they may no longer be reused
/// (TLSV-050). Refusals are never stored.
#[derive(Debug, Default)]
struct Verdicts(Mutex<HashMap<(Vec<u8>, String), u64>>);

impl Verdicts {
    fn key(
        end_entity: &[u8],
        intermediates: &[CertificateDer<'_>],
        host: &str,
    ) -> (Vec<u8>, String) {
        use sha2::Digest as _;
        let mut hash = sha2::Sha256::new();
        for der in core::iter::once(end_entity).chain(intermediates.iter().map(AsRef::as_ref)) {
            hash.update((der.len() as u64).to_be_bytes());
            hash.update(der);
        }
        (hash.finalize().to_vec(), host.to_ascii_lowercase())
    }

    fn reusable(&self, key: &(Vec<u8>, String), now: u64) -> bool {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match map.get(key) {
            Some(&until) if now < until => true,
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    fn keep(&self, key: (Vec<u8>, String), verdict: &Verdict) {
        if let (true, Some(until)) = (verdict.is_valid(), verdict.reusable_until) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key, until);
        }
    }
}

/// The reference host of a connection (TLSV-024).
fn host(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().to_owned(),
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        _ => String::new(),
    }
}

fn seconds(now: UnixTime) -> Timestamp {
    Timestamp(now.as_secs())
}

/// A refusal as rustls reports it, which ends the handshake with a fatal alert (TLSV-002).
fn refusal(verdict: Verdict) -> Error {
    let error = match verdict.code {
        Code::Expired => CertificateError::Expired,
        Code::NotYetValid => CertificateError::NotValidYet,
        Code::NameMismatch => CertificateError::NotValidForName,
        Code::ChainIncomplete => CertificateError::UnknownIssuer,
        Code::OcspRevoked | Code::Revoked => CertificateError::Revoked,
        Code::SignatureInvalid => CertificateError::BadSignature,
        _ => CertificateError::Other(OtherError(Arc::new(Refused(verdict)))),
    };
    Error::InvalidCertificate(error)
}

/// A verdict as an error, for the codes rustls has no name for.
#[derive(Debug)]
pub struct Refused(pub Verdict);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0.code, self.0.detail)
    }
}

impl std::error::Error for Refused {}

fn verify_tls12(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, schemes)
}

/// The `ti` profile as a rustls verifier, over one snapshot of the TI's trust material.
pub struct TiVerifier<R> {
    check: ServerCheck,
    responder: R,
    verdicts: Verdicts,
}

impl<R> fmt::Debug for TiVerifier<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TiVerifier").finish_non_exhaustive()
    }
}

impl<R: RevocationChecker> TiVerifier<R> {
    /// The verifier for `check`, asking `responder` (usually ti-pki's `OcspChecker` over the
    /// host's transport) when no stapled response holds.
    pub fn new(check: ServerCheck, responder: R) -> TiVerifier<R> {
        TiVerifier {
            check,
            responder,
            verdicts: Verdicts::default(),
        }
    }

    /// Judges a server as the handshake does, without one.
    pub fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        host: &str,
        stapled: &[u8],
        now: Timestamp,
    ) -> Verdict {
        let chain: Result<Vec<Certificate>, _> = core::iter::once(end_entity)
            .chain(intermediates)
            .map(|der| Certificate::from_der(der))
            .collect();
        let Ok(chain) = chain else {
            return Verdict::refuse(Code::Invalid, "a certificate does not parse");
        };
        let stapled = (!stapled.is_empty()).then_some(stapled);
        let ti =
            crate::block::block_on(
                self.check
                    .verify(&chain, host, stapled, now, &self.responder),
            );
        let reusable_until = ti.is_valid().then(|| {
            let status_end = ti
                .status_produced
                .unwrap_or(now)
                .0
                .saturating_add(TI_STATUS_REUSE.as_secs());
            ti.not_after.map_or(status_end, |end| end.0.min(status_end))
        });
        Verdict {
            code: ti.code.into(),
            detail: ti.detail,
            warnings: ti.warnings,
            reusable_until,
        }
    }
}

impl<R: RevocationChecker + Send + Sync> ServerCertVerifier for TiVerifier<R> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let host = host(server_name);
        let key = Verdicts::key(end_entity, intermediates, &host);
        let now = seconds(now);
        if self.verdicts.reusable(&key, now.0) {
            return Ok(ServerCertVerified::assertion());
        }
        let verdict = self.verify(end_entity, intermediates, &host, ocsp_response, now);
        self.verdicts.keep(key, &verdict);
        if verdict.is_valid() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refusal(verdict))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12(message, cert, dss, &TI_SCHEMES)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        use ti_pki::algorithms::brainpool;
        let algorithm = match u16::from(dss.scheme) {
            BRAINPOOL_P256_TLS13 => brainpool::ECDSA_BP256R1_SHA256,
            BRAINPOOL_P384_TLS13 => brainpool::ECDSA_BP384R1_SHA384,
            _ => return rustls::crypto::verify_tls13_signature(message, cert, dss, &TI_SCHEMES),
        };
        let bad = || Error::InvalidCertificate(CertificateError::BadSignature);
        let cert = Certificate::from_der(cert).map_err(|_| bad())?;
        algorithm
            .verify_signature(cert.public_key(), message, dss.signature())
            .map(|()| HandshakeSignatureValid::assertion())
            .map_err(|_| bad())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes: Vec<SignatureScheme> = TI_SCHEMES
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect();
        schemes.push(SignatureScheme::Unknown(BRAINPOOL_P256_TLS13));
        schemes.push(SignatureScheme::Unknown(BRAINPOOL_P384_TLS13));
        schemes
    }
}

/// The `web` profile as a rustls verifier, over one set of roots.
pub struct WebVerifier<F> {
    check: WebCheck,
    fetch: F,
    verdicts: Verdicts,
}

impl<F> fmt::Debug for WebVerifier<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebVerifier")
            .field("roots", &self.check.root_count())
            .finish_non_exhaustive()
    }
}

impl<F: Fetch> WebVerifier<F> {
    /// The verifier for `check`, reaching responders and CRL hosts through `fetch`.
    pub fn new(check: WebCheck, fetch: F) -> WebVerifier<F> {
        WebVerifier {
            check,
            fetch,
            verdicts: Verdicts::default(),
        }
    }

    /// What it reaches responders and CRL hosts through.
    pub fn fetch(&self) -> &F {
        &self.fetch
    }

    /// Judges a server as the handshake does, without one.
    pub fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        host: &str,
        stapled: &[u8],
        now: Timestamp,
    ) -> Verdict {
        let chain: Vec<CertificateDer<'_>> = core::iter::once(end_entity.clone())
            .chain(intermediates.iter().cloned())
            .collect();
        let stapled = (!stapled.is_empty()).then_some(stapled);
        crate::block::block_on(self.check.verify(&chain, host, stapled, now, &self.fetch))
    }
}

impl<F: Fetch + Send + Sync> ServerCertVerifier for WebVerifier<F> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let host = host(server_name);
        let key = Verdicts::key(end_entity, intermediates, &host);
        let now = seconds(now);
        if self.verdicts.reusable(&key, now.0) {
            return Ok(ServerCertVerified::assertion());
        }
        let verdict = self.verify(end_entity, intermediates, &host, ocsp_response, now);
        self.verdicts.keep(key, &verdict);
        if verdict.is_valid() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refusal(verdict))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12(message, cert, dss, &WEB_SCHEMES)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &WEB_SCHEMES)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        WEB_SCHEMES
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect()
    }
}
