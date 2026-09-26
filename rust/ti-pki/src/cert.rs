//! [`Certificate`]: an X.509 certificate parsed once, with the extensions TI validation
//! reads decoded up front and its original DER kept for signature checks.
//!
//! Parsing accepts any key type, Brainpool and RSA included. Whether a key is acceptable
//! is decided later — by the anchor a chain must reach and by
//! [`classify_key`](crate::key::classify_key) — never at parse time.

use std::sync::Arc;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc4519::CN;
use const_oid::db::rfc5280::{ID_AD_OCSP, ID_CE_CERTIFICATE_POLICIES};
use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use x509_cert::ext::pkix::name::{DirectoryString, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::admission::AdmissionStatement;
use crate::algorithms::{self, AlgorithmSet};
use crate::time::Timestamp;
use crate::{Error, oid};

/// A parsed X.509 certificate. Cheap to clone: the parsed form is shared.
#[derive(Clone)]
pub struct Certificate(Arc<Parsed>);

struct Parsed {
    der: Vec<u8>,
    tbs: core::ops::Range<usize>,
    inner: x509_cert::Certificate,
    subject_cn: String,
    issuer_cn: String,
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
    not_before: Timestamp,
    not_after: Timestamp,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    key_usage: Option<KeyUsage>,
    ext_key_usage: Vec<ObjectIdentifier>,
    basic_constraints: Option<BasicConstraints>,
    policies: Vec<ObjectIdentifier>,
    ocsp_urls: Vec<String>,
}

impl Certificate {
    /// Parses one DER-encoded certificate.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] if the bytes are not a DER certificate or one of the extensions
    /// read here (key usage, extended key usage, basic constraints, key identifiers,
    /// policies, authority information access) is malformed or repeated.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let inner = x509_cert::Certificate::from_der(der)?;
        let tbs = tbs_range(der)?;
        let tbs_cert = inner.tbs_certificate();

        let subject_key_id = tbs_cert
            .get_extension::<SubjectKeyIdentifier>()?
            .map(|(_, ski)| ski.0.as_bytes().to_vec());
        let authority_key_id = tbs_cert
            .get_extension::<AuthorityKeyIdentifier>()?
            .and_then(|(_, aki)| aki.key_identifier)
            .map(|id| id.as_bytes().to_vec());
        let key_usage = tbs_cert.get_extension::<KeyUsage>()?.map(|(_, ku)| ku);
        let ext_key_usage = tbs_cert
            .get_extension::<ExtendedKeyUsage>()?
            .map_or_else(Vec::new, |(_, eku)| eku.0);
        let basic_constraints = tbs_cert
            .get_extension::<BasicConstraints>()?
            .map(|(_, bc)| bc);
        let policies = tbs_cert
            .get_extension::<CertificatePolicies>()?
            .map_or_else(Vec::new, |(_, cp)| {
                cp.0.into_iter().map(|p| p.policy_identifier).collect()
            });
        let ocsp_urls = tbs_cert
            .get_extension::<AuthorityInfoAccessSyntax>()?
            .map_or_else(Vec::new, |(_, aia)| {
                aia.0
                    .into_iter()
                    .filter(|access| access.access_method == ID_AD_OCSP)
                    .filter_map(|access| match access.access_location {
                        GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                        _ => None,
                    })
                    .collect()
            });

        let parsed = Parsed {
            subject_cn: common_name(tbs_cert.subject()),
            issuer_cn: common_name(tbs_cert.issuer()),
            subject_der: tbs_cert.subject().to_der()?,
            issuer_der: tbs_cert.issuer().to_der()?,
            not_before: timestamp(tbs_cert.validity().not_before),
            not_after: timestamp(tbs_cert.validity().not_after),
            der: der.to_vec(),
            tbs,
            subject_key_id,
            authority_key_id,
            key_usage,
            ext_key_usage,
            basic_constraints,
            policies,
            ocsp_urls,
            inner,
        };
        Ok(Certificate(Arc::new(parsed)))
    }

    /// The certificate as parsed by `x509-cert`, for anything not exposed here.
    pub fn inner(&self) -> &x509_cert::Certificate {
        &self.0.inner
    }

    /// The original DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.0.der
    }

    /// The signed part (`tbsCertificate`), exactly as encoded in [`der`](Self::der).
    pub fn tbs_der(&self) -> &[u8] {
        &self.0.der[self.0.tbs.clone()]
    }

    /// The signature value.
    pub fn signature(&self) -> &[u8] {
        self.0.inner.signature().raw_bytes()
    }

    /// DER contents (without the outer SEQUENCE) of the signature `AlgorithmIdentifier`,
    /// the form [`algorithms::find`] takes.
    ///
    /// # Panics
    ///
    /// Never: the identifier was decoded from DER, so it re-encodes.
    pub fn signature_alg_id(&self) -> Vec<u8> {
        sequence_contents(
            &self
                .0
                .inner
                .signature_algorithm()
                .to_der()
                .expect("re-encodes"),
        )
    }

    /// The subject public key.
    pub fn public_key_info(&self) -> &SubjectPublicKeyInfoOwned {
        self.0.inner.tbs_certificate().subject_public_key_info()
    }

    /// DER contents (without the outer SEQUENCE) of the public key `AlgorithmIdentifier`,
    /// the form [`algorithms::find`] takes.
    ///
    /// # Panics
    ///
    /// Never: the identifier was decoded from DER, so it re-encodes.
    pub fn public_key_alg_id(&self) -> Vec<u8> {
        sequence_contents(
            &self
                .public_key_info()
                .algorithm
                .to_der()
                .expect("re-encodes"),
        )
    }

    /// The raw subject public key (the `subjectPublicKey` BIT STRING contents).
    pub fn public_key(&self) -> &[u8] {
        self.public_key_info().subject_public_key.raw_bytes()
    }

    /// The serial number's big-endian bytes.
    pub fn serial(&self) -> &[u8] {
        self.0.inner.tbs_certificate().serial_number().as_bytes()
    }

    /// The subject name.
    pub fn subject(&self) -> &Name {
        self.0.inner.tbs_certificate().subject()
    }

    /// The issuer name.
    pub fn issuer(&self) -> &Name {
        self.0.inner.tbs_certificate().issuer()
    }

    /// The subject's DER encoding, for exact name comparison.
    pub fn subject_der(&self) -> &[u8] {
        &self.0.subject_der
    }

    /// The issuer's DER encoding, for exact name comparison.
    pub fn issuer_der(&self) -> &[u8] {
        &self.0.issuer_der
    }

    /// The subject's first common name; empty if it has none.
    pub fn subject_cn(&self) -> &str {
        &self.0.subject_cn
    }

    /// The issuer's first common name; empty if it has none.
    pub fn issuer_cn(&self) -> &str {
        &self.0.issuer_cn
    }

    /// Start of the validity period.
    pub fn not_before(&self) -> Timestamp {
        self.0.not_before
    }

    /// End of the validity period.
    pub fn not_after(&self) -> Timestamp {
        self.0.not_after
    }

    /// Whether `at` lies within the validity period, bounds included.
    pub fn is_valid_at(&self, at: Timestamp) -> bool {
        self.0.not_before <= at && at <= self.0.not_after
    }

    /// The subject key identifier.
    pub fn subject_key_id(&self) -> Option<&[u8]> {
        self.0.subject_key_id.as_deref()
    }

    /// The key identifier of the authority key identifier extension.
    pub fn authority_key_id(&self) -> Option<&[u8]> {
        self.0.authority_key_id.as_deref()
    }

    /// The key usage extension.
    pub fn key_usage(&self) -> Option<KeyUsage> {
        self.0.key_usage
    }

    /// The extended key usage purposes; empty without the extension.
    pub fn ext_key_usage(&self) -> &[ObjectIdentifier] {
        &self.0.ext_key_usage
    }

    /// The basic constraints extension.
    pub fn basic_constraints(&self) -> Option<&BasicConstraints> {
        self.0.basic_constraints.as_ref()
    }

    /// Whether basic constraints mark the certificate as a CA.
    pub fn is_ca(&self) -> bool {
        self.0.basic_constraints.as_ref().is_some_and(|bc| bc.ca)
    }

    /// The certificate policy identifiers; empty without the extension.
    pub fn policies(&self) -> &[ObjectIdentifier] {
        &self.0.policies
    }

    /// The OCSP responder URLs from authority information access.
    pub fn ocsp_urls(&self) -> &[String] {
        &self.0.ocsp_urls
    }

    /// Whether the certificate carries an extension with `oid`.
    pub fn has_extension(&self, oid: &ObjectIdentifier) -> bool {
        self.extension_value(oid).is_some()
    }

    /// The OIDs of the extensions marked critical, in certificate order.
    pub fn critical_extensions(&self) -> impl Iterator<Item = ObjectIdentifier> + '_ {
        self.0
            .inner
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .filter(|ext| ext.critical)
            .map(|ext| ext.extn_id)
    }

    /// The DER value of the extension with `oid`, if present.
    pub fn extension_value(&self, oid: &ObjectIdentifier) -> Option<&[u8]> {
        self.0
            .inner
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|ext| ext.extn_id == *oid)
            .map(|ext| ext.extn_value.as_bytes())
    }

    /// The gematik admission statement (profession items, profession OIDs, registration
    /// number); `None` if the certificate has no admission extension.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] or [`Error::Malformed`] if the extension is present but cannot be
    /// decoded.
    pub fn admission(&self) -> Result<Option<AdmissionStatement>, Error> {
        self.extension_value(&oid::ADMISSION_EXTENSION)
            .map(AdmissionStatement::from_der)
            .transpose()
    }

    /// Whether the certificate asserts the certificate policy `policy`.
    pub fn has_policy(&self, policy: &ObjectIdentifier) -> bool {
        self.0.policies.contains(policy)
    }

    /// Checks that `issuer`'s key signed this certificate, with an algorithm from
    /// `algorithms`.
    ///
    /// # Errors
    ///
    /// [`SignatureError::UnsupportedAlgorithm`] if no algorithm in the set handles the
    /// issuer's key with this certificate's signature algorithm (an RSA issuer without
    /// RSA support, say), [`SignatureError::Invalid`] if the signature does not verify.
    pub fn verify_signed_by(
        &self,
        issuer: &Certificate,
        algorithms: &AlgorithmSet,
    ) -> Result<(), SignatureError> {
        let alg = algorithms::find(
            algorithms,
            &issuer.public_key_alg_id(),
            &self.signature_alg_id(),
        )
        .ok_or_else(|| SignatureError::UnsupportedAlgorithm {
            key: crate::key::classify_key(issuer.public_key_info(), Timestamp(0)).1,
            signature: signature_name(&self.inner().signature_algorithm().oid),
        })?;
        alg.verify_signature(issuer.public_key(), self.tbs_der(), self.signature())
            .map_err(|_| SignatureError::Invalid)
    }

    /// Whether the certificate is self-signed: issuer equals subject and its own key
    /// verifies its signature.
    pub fn is_self_signed(&self, algorithms: &AlgorithmSet) -> bool {
        self.issuer_der() == self.subject_der() && self.verify_signed_by(self, algorithms).is_ok()
    }

    /// Whether the certificate has a certificate policies extension at all.
    pub fn has_policies_extension(&self) -> bool {
        self.has_extension(&ID_CE_CERTIFICATE_POLICIES)
    }
}

/// Why [`Certificate::verify_signed_by`] failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// No configured algorithm handles this key and signature algorithm.
    #[error(
        "no configured algorithm verifies a {signature} signature by an issuer key of type {key}"
    )]
    UnsupportedAlgorithm {
        /// The issuer key, e.g. `RSA 2048`.
        key: String,
        /// The signature algorithm, e.g. `sha256WithRSAEncryption`.
        signature: String,
    },
    /// The signature does not verify.
    #[error("signature does not verify")]
    Invalid,
}

fn signature_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".into(),
        other => other.to_owned(),
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.0.der == other.0.der
    }
}

impl Eq for Certificate {}

impl core::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificate")
            .field("subject", &self.0.subject_cn)
            .field("issuer", &self.0.issuer_cn)
            .finish_non_exhaustive()
    }
}

/// Parses every `CERTIFICATE` block in `pem`, in order. Other blocks (keys, CSRs) and
/// text between blocks are skipped. Input without certificates yields an empty list;
/// callers that need one must check.
///
/// # Errors
///
/// [`Error::Pem`] for a malformed block, [`Error::Der`] for a certificate block that
/// does not parse.
pub fn parse_pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>, Error> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"-----END ";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = find(rest, BEGIN) {
        let block_and_rest = &rest[start..];
        let Some(end) = find(block_and_rest, END) else {
            break;
        };
        let after_end = &block_and_rest[end + END.len()..];
        let Some(close) = find(after_end, b"-----") else {
            break;
        };
        let block_len = end + END.len() + close + 5;
        let block = &block_and_rest[..block_len];
        let (label, der) = pem_rfc7468::decode_vec(block)?;
        if label == "CERTIFICATE" {
            certificates.push(Certificate::from_der(&der)?);
        }
        rest = &block_and_rest[block_len..];
    }
    Ok(certificates)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The byte range of `tbsCertificate` inside the certificate's DER.
fn tbs_range(der: &[u8]) -> Result<core::ops::Range<usize>, Error> {
    let mut outer = SliceReader::new(der)?;
    let header = der::Header::decode(&mut outer)?;
    let offset = usize::try_from(outer.position())?;
    let mut inner = SliceReader::new(&der[offset..offset + usize::try_from(header.length())?])?;
    let tbs = inner.tlv_bytes()?;
    Ok(offset..offset + tbs.len())
}

fn sequence_contents(sequence: &[u8]) -> Vec<u8> {
    AnyRef::from_der(sequence).map_or_else(|_| Vec::new(), |any| any.value().to_vec())
}

fn timestamp(time: x509_cert::time::Time) -> Timestamp {
    Timestamp(time.to_unix_duration().as_secs())
}

fn common_name(name: &Name) -> String {
    name.iter_rdn()
        .flat_map(x509_cert::name::RelativeDistinguishedName::iter)
        .find(|atv| atv.oid == CN)
        .and_then(|atv| atv.value.decode_as::<DirectoryString>().ok())
        .map(|value| value.value().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::algorithms;

    pub(crate) const RCA5: &str = include_str!("../tests/fixtures/rca5-test-only.pem");
    pub(crate) const SMCB_CA51: &str = include_str!("../tests/fixtures/smcb-ca51-test-only.pem");
    pub(crate) const SMCB_EE: &str = include_str!("../tests/fixtures/smcb-ee-test-only.pem");
    pub(crate) const RCA2_RSA: &str = include_str!("../tests/fixtures/rca2-rsa-test-only.pem");

    pub(crate) fn fixture(pem: &str) -> Certificate {
        let mut certs = parse_pem_certificates(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
        certs.remove(0)
    }

    fn verify(issuer: &Certificate, subject: &Certificate) -> bool {
        subject
            .verify_signed_by(issuer, algorithms::DEFAULT)
            .is_ok()
    }

    #[test]
    fn brainpool_fixture_fields() {
        let ee = fixture(SMCB_EE);
        assert_eq!(ee.subject_cn(), "Arztpraxis Bernd Rosenstrauch TEST-ONLY");
        assert_eq!(ee.issuer_cn(), "GEM.SMCB-CA51 TEST-ONLY");
        assert!(!ee.is_ca());
        assert!(ee.subject_key_id().is_some());
        assert_eq!(ee.authority_key_id(), fixture(SMCB_CA51).subject_key_id());
        assert!(ee.not_before() < ee.not_after());
        assert!(ee.is_valid_at(ee.not_before()) && ee.is_valid_at(ee.not_after()));
        assert!(!ee.is_valid_at(Timestamp(ee.not_after().0 + 1)));
        assert!(!ee.ocsp_urls().is_empty());
        assert_eq!(ee.issuer_der(), fixture(SMCB_CA51).subject_der());

        let ca = fixture(SMCB_CA51);
        assert!(ca.is_ca());
        assert_eq!(ca.basic_constraints().unwrap().path_len_constraint, Some(0));
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn tbs_bytes_verify_through_the_brainpool_chain() {
        let (rca5, ca51, ee) = (fixture(RCA5), fixture(SMCB_CA51), fixture(SMCB_EE));
        assert!(verify(&rca5, &rca5));
        assert!(verify(&rca5, &ca51));
        assert!(verify(&ca51, &ee));
        assert!(!verify(&rca5, &ee));
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn openssl_nist_chain() {
        let pki = crate::testing::TestPki::new();
        assert_eq!(pki.ee_zeta.subject_cn(), "zeta.ti-dienste.de TEST-ONLY");
        assert_eq!(pki.ee_zeta.issuer_cn(), "GEM.SubCA-Komp TEST-ONLY");
        assert!(verify(&pki.sub_ca_komp, &pki.ee_zeta));
        assert!(verify(&pki.rca7, &pki.rca7));
        assert!(!verify(&pki.rca7, &pki.ee_zeta));
        assert_eq!(
            pki.ee_zeta.authority_key_id(),
            pki.sub_ca_komp.subject_key_id()
        );
        assert_eq!(
            pki.ee_zeta.ext_key_usage(),
            [const_oid::db::rfc5280::ID_KP_SERVER_AUTH]
        );
    }

    #[cfg(all(feature = "brainpool", feature = "rsa"))]
    #[test]
    fn openssl_rsa_pss_chain() {
        let pki = crate::testing::TestPki::new();
        assert!(verify(&pki.rca_rsa, &pki.rca_rsa));
        assert!(verify(&pki.rca_rsa, &pki.ee_rsa_pss));
    }

    #[test]
    fn rsa_issuer_needs_an_rsa_algorithm() {
        let rca2 = fixture(RCA2_RSA);
        assert_eq!(
            rca2.verify_signed_by(&rca2, algorithms::STANDARD),
            Err(SignatureError::UnsupportedAlgorithm {
                key: "RSA 2048".into(),
                signature: "sha256WithRSAEncryption".into(),
            })
        );
        #[cfg(feature = "rsa")]
        assert_eq!(rca2.verify_signed_by(&rca2, algorithms::DEFAULT), Ok(()));
    }

    #[test]
    fn rsa_root_parses() {
        let rca2 = fixture(RCA2_RSA);
        assert_eq!(rca2.subject_cn(), "GEM.RCA2 TEST-ONLY");
        assert_eq!(
            rca2.public_key_info().algorithm.oid,
            const_oid::db::rfc5912::RSA_ENCRYPTION
        );
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn foreign_key_types_parse() {
        let pki = crate::testing::TestPki::new();
        let (status, key) = crate::key::classify_key(pki.ee_p521.public_key_info(), Timestamp(0));
        assert_eq!(
            (status, key.as_str()),
            (crate::key::KeyStatus::NotAdmissible, "ECDSA P-521")
        );
        assert!(verify(&pki.rca7, &pki.ee_p521));
    }

    #[test]
    fn pem_parsing() {
        let two = format!("{RCA5}\n{SMCB_CA51}");
        let certs = parse_pem_certificates(two.as_bytes()).unwrap();
        assert_eq!(
            certs
                .iter()
                .map(Certificate::subject_cn)
                .collect::<Vec<_>>(),
            ["GEM.RCA5 TEST-ONLY", "GEM.SMCB-CA51 TEST-ONLY"]
        );

        let key_block = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        let mixed = format!("preamble\n{key_block}{RCA5}\ntrailer");
        assert_eq!(parse_pem_certificates(mixed.as_bytes()).unwrap().len(), 1);

        assert!(parse_pem_certificates(b"").unwrap().is_empty());
        assert!(parse_pem_certificates(b"no pem here").unwrap().is_empty());
    }
}
