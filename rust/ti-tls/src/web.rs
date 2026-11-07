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

//! The `web` profile of `spec/pki-validation`: a server on the internet, verified against the
//! host system's roots with the requirements gematik and the ZETA SDK add (TLSV-040 to 045).

use core::time::Duration;

use const_oid::ObjectIdentifier;
use der::Decode;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use ti_pki::ocsp::{ResponseCheck, request, verify_response};
use ti_pki::{RevocationStatus, Timestamp};
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy,
};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{CrlDistributionPoints, KeyUsages};

use crate::algorithms::WEB_CERTIFICATE_ALGORITHMS;
use crate::fetch::Fetch;
use crate::verdict::{Code, Verdict};

/// TLSV-045: the CA/Browser Forum's longest validity period.
pub const MAX_VALIDITY: Duration = Duration::from_hours(398 * 24);

/// TLSV-051: how long a revocation status is reused at most.
pub const MAX_STATUS_REUSE: Duration = Duration::from_hours(24);

/// The `web` profile over a set of roots.
#[derive(Clone, Debug)]
pub struct WebCheck {
    roots: Vec<CertificateDer<'static>>,
    anchors: Vec<TrustAnchor<'static>>,
}

impl WebCheck {
    /// The check over `roots`, the host system's default store (TLSV-040); a root that does
    /// not parse is left out.
    pub fn new(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> WebCheck {
        let roots: Vec<CertificateDer<'static>> = roots.into_iter().collect();
        let anchors = roots
            .iter()
            .filter_map(|root| webpki::anchor_from_trusted_cert(root).ok())
            .map(|anchor| anchor.to_owned())
            .collect();
        WebCheck { roots, anchors }
    }

    /// The check over the host system's default roots, as its TLS stack and Go's standard
    /// library read them (TLSV-040); in a container, the distribution's bundle.
    pub fn system() -> WebCheck {
        WebCheck::new(rustls_native_certs::load_native_certs().certs)
    }

    /// How many roots the check trusts.
    pub fn root_count(&self) -> usize {
        self.anchors.len()
    }

    /// Judges the server that presented `chain` (end entity first) for a connection to
    /// `host`, at `now`, with the OCSP response it stapled; `fetch` reaches its responder
    /// and CRL host, asked only about a server that passed everything else.
    pub async fn verify(
        &self,
        chain: &[CertificateDer<'_>],
        host: &str,
        stapled: Option<&[u8]>,
        now: Timestamp,
        fetch: &impl Fetch,
    ) -> Verdict {
        let Some((leaf_der, sent)) = chain.split_first() else {
            return Verdict::refuse(Code::ChainIncomplete, "the server sent no certificate");
        };
        let Ok(leaf) = EndEntityCert::try_from(leaf_der) else {
            return Verdict::refuse(Code::Invalid, "the end entity does not parse");
        };
        let time = UnixTime::since_unix_epoch(Duration::from_secs(now.0));
        let path = match leaf.verify_for_usage(
            WEB_CERTIFICATE_ALGORITHMS,
            &self.anchors,
            sent,
            time,
            KeyUsage::server_auth(),
            None,
            None,
        ) {
            Ok(path) => path,
            Err(e) => return path_refusal(&e, sent),
        };
        let Ok(leaf_info) = Info::parse(leaf_der) else {
            return Verdict::refuse(Code::Invalid, "the end entity does not parse");
        };
        if !leaf_info.signs() {
            return Verdict::refuse(Code::KeyUsageMismatch, "keyUsage without digitalSignature");
        }
        if !leaf_info.key.admissible_end_entity() {
            return Verdict::refuse(
                Code::KeyNotAdmissible,
                format!("end entity key {}", leaf_info.key),
            );
        }
        for ca in path.intermediate_certificates() {
            match Info::parse(ca.der().as_ref()) {
                Ok(info) if info.key.admissible_ca() => {}
                Ok(info) => {
                    return Verdict::refuse(Code::KeyNotAdmissible, format!("CA key {}", info.key));
                }
                Err(()) => return Verdict::refuse(Code::Invalid, "a CA does not parse"),
            }
        }
        if let Err(e) = leaf.verify_is_valid_for_subject_name(&server_name(host)) {
            return Verdict::refuse(Code::NameMismatch, format!("{host}: {e}"));
        }
        if leaf_info.not_after.saturating_sub(leaf_info.not_before) > MAX_VALIDITY.as_secs() {
            return Verdict::refuse(Code::ValidityTooLong, "valid for more than 398 days");
        }
        let issuer = path
            .intermediate_certificates()
            .next()
            .map(|ca| ca.der().into_owned())
            .or_else(|| self.issuing_root(leaf_der));
        let Some(issuer) = issuer else {
            return Verdict::refuse(Code::Invalid, "the issuer is not at hand");
        };
        self.revocation(
            &leaf, leaf_der, &issuer, sent, stapled, time, now, &leaf_info, fetch,
        )
        .await
    }

    /// The root that issued `leaf` directly, for its OCSP CertID.
    fn issuing_root(&self, leaf: &CertificateDer<'_>) -> Option<CertificateDer<'static>> {
        let leaf = ti_pki::Certificate::from_der(leaf).ok()?;
        self.roots
            .iter()
            .find(|root| {
                ti_pki::Certificate::from_der(root)
                    .is_ok_and(|root| root.subject_der() == leaf.issuer_der())
            })
            .cloned()
    }

    /// TLSV-044: stapled OCSP, the responder, the CRL, in that order; the first status
    /// decides, and without one the server is refused.
    #[allow(
        clippy::too_many_arguments,
        reason = "one call site, each a distinct input"
    )]
    async fn revocation(
        &self,
        leaf: &EndEntityCert<'_>,
        leaf_der: &CertificateDer<'_>,
        issuer_der: &CertificateDer<'_>,
        sent: &[CertificateDer<'_>],
        stapled: Option<&[u8]>,
        time: UnixTime,
        now: Timestamp,
        info: &Info,
        fetch: &impl Fetch,
    ) -> Verdict {
        let (Ok(cert), Ok(issuer)) = (
            ti_pki::Certificate::from_der(leaf_der),
            ti_pki::Certificate::from_der(issuer_der),
        ) else {
            return Verdict::refuse(Code::Invalid, "the end entity or its issuer does not parse");
        };
        let ocsp = |der: &[u8]| -> Option<Verdict> {
            let check = ResponseCheck {
                allow_missing_cert_hash: true,
                ..ResponseCheck::stapled(now, ti_pki::algorithms::DEFAULT)
            };
            let status = verify_response(der, &cert, &issuer, &check).ok()?;
            match status.status {
                RevocationStatus::Good => Some(accepted(info, now, status.next_update)),
                RevocationStatus::Revoked => Some(Verdict::refuse(Code::Revoked, "revoked (OCSP)")),
                RevocationStatus::Unknown => None,
            }
        };
        if let Some(verdict) = stapled.and_then(ocsp) {
            return verdict;
        }
        for url in cert.ocsp_urls() {
            if let Some(verdict) = fetch
                .ocsp(url, &request(&cert, &issuer))
                .await
                .as_deref()
                .and_then(ocsp)
            {
                return verdict;
            }
        }
        for url in &info.crl_urls {
            let Some(der) = fetch.crl(url).await else {
                continue;
            };
            let Ok(crl) = BorrowedCertRevocationList::from_der(&der) else {
                continue;
            };
            let crls = [&CertRevocationList::Borrowed(crl)];
            let Ok(options) = RevocationOptionsBuilder::new(&crls) else {
                continue;
            };
            let options = options
                .with_depth(RevocationCheckDepth::EndEntity)
                .with_status_policy(UnknownStatusPolicy::Deny)
                .with_expiration_policy(ExpirationPolicy::Enforce)
                .build();
            match leaf.verify_for_usage(
                WEB_CERTIFICATE_ALGORITHMS,
                &self.anchors,
                sent,
                time,
                KeyUsage::server_auth(),
                Some(options),
                None,
            ) {
                Ok(_) => return accepted(info, now, crl_next_update(&der)),
                Err(webpki::Error::CertRevoked) => {
                    return Verdict::refuse(Code::Revoked, "revoked (CRL)");
                }
                Err(_) => {}
            }
        }
        Verdict::refuse(
            Code::RevocationUnavailable,
            "no revocation source gave a status",
        )
    }
}

/// The `nextUpdate` of a CRL webpki has accepted (TLSV-050). webpki checks it but does not
/// expose it, so the list is read once more; a list without one bounds nothing.
fn crl_next_update(der: &[u8]) -> Option<Timestamp> {
    let crl =
        x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(der).ok()?;
    let next = crl.tbs_cert_list.next_update?;
    Some(Timestamp(next.to_unix_duration().as_secs()))
}

/// An accepted verdict, reusable until the earliest of `notAfter`, the status's
/// `nextUpdate` and a day (TLSV-050, TLSV-051).
fn accepted(info: &Info, now: Timestamp, next_update: Option<Timestamp>) -> Verdict {
    let until = [
        Some(info.not_after),
        next_update.map(|t| t.0),
        Some(now.0.saturating_add(MAX_STATUS_REUSE.as_secs())),
    ]
    .into_iter()
    .flatten()
    .min();
    Verdict {
        code: Code::Valid,
        detail: "valid".into(),
        warnings: Vec::new(),
        reusable_until: until,
    }
}

fn path_refusal(e: &webpki::Error, sent: &[CertificateDer<'_>]) -> Verdict {
    use webpki::Error as E;
    let code = match e {
        E::UnknownIssuer => Code::ChainIncomplete,
        E::CertExpired { .. } => Code::Expired,
        E::CertNotValidYet { .. } => Code::NotYetValid,
        E::RequiredEkuNotFoundContext(_) => Code::KeyUsageMismatch,
        E::UnsupportedSignatureAlgorithmContext(_) => Code::SignatureAlgorithmNotAllowed,
        // A CA key outside what the profile admits fails as a signature it cannot verify.
        E::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        | E::InvalidSignatureForPublicKey
            if sent
                .iter()
                .any(|c| Info::parse(c.as_ref()).is_ok_and(|i| !i.key.admissible_ca())) =>
        {
            Code::KeyNotAdmissible
        }
        E::InvalidSignatureForPublicKey
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => Code::SignatureInvalid,
        E::UnsupportedCriticalExtension => Code::UnrecognizedCriticalExtension,
        _ => Code::Invalid,
    };
    Verdict::refuse(code, e.to_string())
}

/// TLSV-024: the reference host, without a trailing dot.
fn server_name(host: &str) -> ServerName<'static> {
    let host = host.strip_suffix('.').unwrap_or(host);
    ServerName::try_from(host.to_ascii_lowercase())
        .unwrap_or_else(|_| ServerName::try_from("invalid.invalid").expect("a valid name"))
}

/// A public key as the profile judges it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    P256,
    P384,
    Rsa(usize),
    Other,
}

impl Key {
    /// TLSV-041.
    fn admissible_end_entity(self) -> bool {
        matches!(self, Key::P256 | Key::P384) || matches!(self, Key::Rsa(bits) if bits >= 3000)
    }

    /// TLSV-042.
    fn admissible_ca(self) -> bool {
        matches!(self, Key::P256 | Key::P384) || matches!(self, Key::Rsa(bits) if bits >= 2048)
    }
}

impl core::fmt::Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Key::P256 => f.write_str("ECDSA P-256"),
            Key::P384 => f.write_str("ECDSA P-384"),
            Key::Rsa(bits) => write!(f, "RSA {bits}"),
            Key::Other => f.write_str("not admitted"),
        }
    }
}

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: der::asn1::UintRef<'a>,
    #[allow(
        dead_code,
        reason = "part of the structure; only the modulus is judged"
    )]
    exponent: der::asn1::UintRef<'a>,
}

/// What the profile reads from a certificate beyond the path.
struct Info {
    key: Key,
    key_usage: Option<x509_cert::ext::pkix::KeyUsage>,
    not_before: u64,
    not_after: u64,
    crl_urls: Vec<String>,
}

impl Info {
    fn parse(der: &[u8]) -> Result<Info, ()> {
        let cert = x509_cert::Certificate::from_der(der).map_err(|_| ())?;
        let tbs = cert.tbs_certificate();
        let spki = tbs.subject_public_key_info();
        let key = if spki.algorithm.oid == EC_PUBLIC_KEY {
            match spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            {
                Some(curve) if curve == P256 => Key::P256,
                Some(curve) if curve == P384 => Key::P384,
                _ => Key::Other,
            }
        } else if spki.algorithm.oid == RSA {
            spki.subject_public_key
                .as_bytes()
                .and_then(|bits| RsaPublicKey::from_der(bits).ok())
                .map_or(Key::Other, |rsa| {
                    let modulus = rsa.modulus.as_bytes();
                    let lead = modulus.first().map_or(8, |b| b.leading_zeros() as usize);
                    Key::Rsa(modulus.len() * 8 - lead)
                })
        } else {
            Key::Other
        };
        let mut key_usage = None;
        let mut crl_urls = Vec::new();
        for ext in tbs.extensions().map(Vec::as_slice).unwrap_or_default() {
            if ext.extn_id == KEY_USAGE {
                key_usage =
                    x509_cert::ext::pkix::KeyUsage::from_der(ext.extn_value.as_bytes()).ok();
            } else if ext.extn_id == CRL_DISTRIBUTION_POINTS
                && let Ok(points) = CrlDistributionPoints::from_der(ext.extn_value.as_bytes())
            {
                for point in points.0 {
                    if let Some(DistributionPointName::FullName(names)) = point.distribution_point {
                        crl_urls.extend(names.into_iter().filter_map(|name| match name {
                            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                            _ => None,
                        }));
                    }
                }
            }
        }
        let validity = tbs.validity();
        Ok(Info {
            key,
            key_usage,
            not_before: validity.not_before.to_unix_duration().as_secs(),
            not_after: validity.not_after.to_unix_duration().as_secs(),
            crl_urls,
        })
    }

    /// TLSV-022: a key usage, where present, with `digitalSignature`.
    fn signs(&self) -> bool {
        self.key_usage
            .as_ref()
            .is_none_or(|ku| ku.0.contains(KeyUsages::DigitalSignature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TLSV-050: a verdict that rests on a CRL is not reused past the list's `nextUpdate`.
    #[test]
    fn tlsv_050_a_crl_verdict_ends_at_the_lists_next_update() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/pki-validation/testdata/crl/web-ca-empty.der"
        );
        let der = std::fs::read(path).unwrap();
        // 2026-01-08T00:00:00Z.
        assert_eq!(crl_next_update(&der), Some(Timestamp(1_767_830_400)));
        assert_eq!(crl_next_update(b"not a list"), None);
    }
}
