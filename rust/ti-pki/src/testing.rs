//! Test PKIs for this crate's tests and for downstream crates (feature `test-util`).
//!
//! Keys are derived from a label and signatures are deterministic (RFC 6979), so every
//! certificate built here is reproducible byte for byte. Certificates are assembled from
//! plain DER structures, so a test can build exactly the certificate it needs — odd
//! extensions and foreign keys included — the way `gempki`'s `internal/testca` does.

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::{ID_AD_OCSP, ID_PE_AUTHORITY_INFO_ACCESS};
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1};
use der::asn1::{Any, BitString, Ia5String, OctetString, Uint, UtcTime};
use der::{Decode, Encode, Sequence};
use ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints,
    CertificatePolicies, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Time;

use crate::Certificate;
use crate::admission::AdmissionStatement;
use crate::time::Timestamp;

/// The curve of a test key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Curve {
    /// NIST P-256.
    P256,
    /// brainpoolP256r1, the TI's curve.
    #[cfg(feature = "brainpool")]
    BrainpoolP256r1,
}

/// A signing key derived deterministically from a label.
#[derive(Clone)]
pub struct TestKey {
    inner: KeyInner,
}

#[derive(Clone)]
enum KeyInner {
    P256(p256::ecdsa::SigningKey),
    #[cfg(feature = "brainpool")]
    Bp256(ecdsa::SigningKey<bp256::BrainpoolP256r1>),
}

impl core::fmt::Debug for TestKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestKey")
            .field("curve", &self.curve())
            .finish()
    }
}

impl TestKey {
    /// The key for `label` on `curve`; the same label always yields the same key.
    ///
    /// # Panics
    ///
    /// Only if SHA-256 of the label is not a valid scalar, which has probability
    /// around 2⁻¹²⁸ and does not happen for any label in this crate's tests.
    pub fn new(curve: Curve, label: &str) -> Self {
        let seed = Sha256::digest(label.as_bytes());
        let inner = match curve {
            Curve::P256 => {
                KeyInner::P256(p256::ecdsa::SigningKey::from_slice(&seed).expect("scalar"))
            }
            #[cfg(feature = "brainpool")]
            Curve::BrainpoolP256r1 => {
                KeyInner::Bp256(ecdsa::SigningKey::from_slice(&seed).expect("scalar"))
            }
        };
        TestKey { inner }
    }

    /// The key's curve.
    pub fn curve(&self) -> Curve {
        match self.inner {
            KeyInner::P256(_) => Curve::P256,
            #[cfg(feature = "brainpool")]
            KeyInner::Bp256(_) => Curve::BrainpoolP256r1,
        }
    }

    /// The public key as a `SubjectPublicKeyInfo`.
    ///
    /// # Panics
    ///
    /// Never: an uncompressed point always fits a bit string.
    pub fn spki(&self) -> SubjectPublicKeyInfoOwned {
        let (curve, point) = match &self.inner {
            KeyInner::P256(key) => (
                SECP_256_R_1,
                key.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            ),
            #[cfg(feature = "brainpool")]
            KeyInner::Bp256(key) => (
                ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7"),
                key.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            ),
        };
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::from(&curve)),
            },
            subject_public_key: BitString::from_bytes(&point).expect("bit string"),
        }
    }

    /// ECDSA-SHA-256 signature over `message`, DER encoded.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.inner {
            KeyInner::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            #[cfg(feature = "brainpool")]
            KeyInner::Bp256(key) => {
                let signature: ecdsa::Signature<bp256::BrainpoolP256r1> = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
        }
    }
}

/// The key identifier `issue` puts in SKI/AKI for a public key: the first 20 bytes of
/// its SHA-256.
pub fn key_id(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha256::digest(spki.subject_public_key.raw_bytes())[..20].to_vec()
}

/// What a test certificate contains. Start from [`CertSpec::ca`] or [`CertSpec::ee`] and
/// adjust fields with struct update.
#[derive(Clone, Debug)]
pub struct CertSpec {
    /// Subject in RFC 4514 form, e.g. `CN=GEM.RCA1 TEST-ONLY,O=gematik GmbH`.
    pub subject: String,
    /// Serial number.
    pub serial: u64,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
    /// Basic constraints: `None` omits the extension, `Some((ca, path_len))` sets it.
    pub basic_constraints: Option<(bool, Option<u8>)>,
    /// Key usage; `None` omits the extension.
    pub key_usage: Option<KeyUsage>,
    /// Extended key usage purposes; empty omits the extension.
    pub ext_key_usage: Vec<ObjectIdentifier>,
    /// Certificate policies; empty omits the extension.
    pub policies: Vec<ObjectIdentifier>,
    /// OCSP responder URL for authority information access.
    pub ocsp_url: Option<String>,
    /// Admission extension.
    pub admission: Option<AdmissionStatement>,
    /// Further extensions, appended verbatim.
    pub extra_extensions: Vec<Extension>,
}

impl CertSpec {
    /// A CA valid from `not_before` to `not_after`: basic constraints CA, key usage
    /// certificate and CRL signing.
    pub fn ca(subject: &str, not_before: Timestamp, not_after: Timestamp) -> Self {
        CertSpec {
            subject: subject.to_owned(),
            serial: serial_for(subject),
            not_before,
            not_after,
            basic_constraints: Some((true, None)),
            key_usage: Some(KeyUsage(
                x509_cert::ext::pkix::KeyUsages::KeyCertSign
                    | x509_cert::ext::pkix::KeyUsages::CRLSign,
            )),
            ext_key_usage: Vec::new(),
            policies: Vec::new(),
            ocsp_url: None,
            admission: None,
            extra_extensions: Vec::new(),
        }
    }

    /// An end entity valid from `not_before` to `not_after`: key usage digital
    /// signature, no basic constraints.
    pub fn ee(subject: &str, not_before: Timestamp, not_after: Timestamp) -> Self {
        CertSpec {
            basic_constraints: None,
            key_usage: Some(KeyUsage(
                x509_cert::ext::pkix::KeyUsages::DigitalSignature.into(),
            )),
            ..Self::ca(subject, not_before, not_after)
        }
    }
}

/// A certificate with its key.
#[derive(Clone, Debug)]
pub struct Node {
    /// The certificate.
    pub cert: Certificate,
    /// Its private key.
    pub key: TestKey,
}

impl Node {
    /// A self-signed root with a key for `label` on `curve`.
    pub fn root(curve: Curve, label: &str, spec: &CertSpec) -> Node {
        let key = TestKey::new(curve, label);
        let spki = key.spki();
        let cert = build(spec, &spki, None, &key);
        Node { cert, key }
    }

    /// A certificate for a new key (`label` on `curve`) issued by this node.
    #[must_use]
    pub fn issue(&self, curve: Curve, label: &str, spec: &CertSpec) -> Node {
        let key = TestKey::new(curve, label);
        let cert = self.issue_for(&key.spki(), spec);
        Node { cert, key }
    }

    /// A certificate for an arbitrary public key issued by this node, e.g. a key type
    /// the TI never admits.
    pub fn issue_for(&self, spki: &SubjectPublicKeyInfoOwned, spec: &CertSpec) -> Certificate {
        build(spec, spki, Some(&self.cert), &self.key)
    }
}

#[derive(Sequence)]
struct Tbs {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: u8,
    serial: Uint,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: TestValidity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

#[derive(Sequence)]
struct TestValidity {
    not_before: Time,
    not_after: Time,
}

#[derive(Sequence)]
struct TestCertificate {
    tbs: Any,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// Builds and signs a certificate; `issuer` `None` means self-signed.
///
/// # Panics
///
/// On a spec that cannot be encoded (an unparsable subject, a date outside the UTCTime
/// range). Test code only.
pub fn build(
    spec: &CertSpec,
    spki: &SubjectPublicKeyInfoOwned,
    issuer: Option<&Certificate>,
    signer: &TestKey,
) -> Certificate {
    let subject: Name = spec.subject.parse().expect("RFC 4514 subject");
    let issuer_name = issuer.map_or_else(|| subject.clone(), |c| c.subject().clone());
    let issuer_key_id = issuer.map_or_else(
        || key_id(spki),
        |c| {
            c.subject_key_id()
                .map_or_else(|| key_id(c.public_key_info()), <[u8]>::to_vec)
        },
    );
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA_256,
        parameters: None,
    };
    let tbs = Tbs {
        version: 2,
        serial: Uint::new(&spec.serial.to_be_bytes()).expect("serial"),
        signature: signature_algorithm.clone(),
        issuer: issuer_name,
        validity: TestValidity {
            not_before: time(spec.not_before),
            not_after: time(spec.not_after),
        },
        subject,
        subject_public_key_info: spki.clone(),
        extensions: Some(extensions(spec, spki, &issuer_key_id)),
    };
    let tbs_der = tbs.to_der().expect("encode tbs");
    let signature = signer.sign(&tbs_der);
    let certificate = TestCertificate {
        tbs: Any::from_der(&tbs_der).expect("tbs"),
        signature_algorithm,
        signature: BitString::from_bytes(&signature).expect("signature"),
    };
    Certificate::from_der(&certificate.to_der().expect("encode certificate"))
        .expect("test certificate parses")
}

fn extensions(
    spec: &CertSpec,
    spki: &SubjectPublicKeyInfoOwned,
    issuer_key_id: &[u8],
) -> Vec<Extension> {
    let mut out = vec![
        extension(
            &SubjectKeyIdentifier(OctetString::new(key_id(spki)).expect("ski")),
            false,
        ),
        extension(
            &AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(issuer_key_id).expect("aki")),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
            false,
        ),
    ];
    if let Some((ca, path_len)) = spec.basic_constraints {
        out.push(extension(
            &BasicConstraints {
                ca,
                path_len_constraint: path_len,
            },
            true,
        ));
    }
    if let Some(key_usage) = spec.key_usage {
        out.push(extension(&key_usage, true));
    }
    if !spec.ext_key_usage.is_empty() {
        out.push(extension(
            &ExtendedKeyUsage(spec.ext_key_usage.clone()),
            false,
        ));
    }
    if !spec.policies.is_empty() {
        let policies = spec
            .policies
            .iter()
            .map(|oid| PolicyInformation {
                policy_identifier: *oid,
                policy_qualifiers: None,
            })
            .collect();
        out.push(extension(&CertificatePolicies(policies), false));
    }
    if let Some(url) = &spec.ocsp_url {
        let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: ID_AD_OCSP,
            access_location: GeneralName::UniformResourceIdentifier(
                Ia5String::new(url).expect("IA5 URL"),
            ),
        }]);
        out.push(Extension {
            extn_id: ID_PE_AUTHORITY_INFO_ACCESS,
            critical: false,
            extn_value: OctetString::new(aia.to_der().expect("aia")).expect("aia"),
        });
    }
    if let Some(admission) = &spec.admission {
        out.push(Extension {
            extn_id: crate::oid::ADMISSION_EXTENSION,
            critical: false,
            extn_value: OctetString::new(admission.to_der()).expect("admission"),
        });
    }
    out.extend(spec.extra_extensions.iter().cloned());
    out
}

fn extension<T: Encode + const_oid::AssociatedOid>(value: &T, critical: bool) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("extension")).expect("extension"),
    }
}

fn time(at: Timestamp) -> Time {
    Time::UtcTime(
        UtcTime::from_unix_duration(core::time::Duration::from_secs(at.0)).expect("UTCTime range"),
    )
}

fn serial_for(subject: &str) -> u64 {
    let digest = Sha256::digest(subject.as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) >> 1
}
