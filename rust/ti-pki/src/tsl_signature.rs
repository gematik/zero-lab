//! The signature of a TSL and its signer (`spec/tsl-xmldsig`, parts A and B).
//!
//! [`verify`] is part A: `ti-xmldsig` checks the XML against the fixed XMLDSig/XAdES
//! profile and the reference digests; this module parses the signer certificate, binds
//! it by serial number, requires a brainpoolP256r1 key and verifies the ECDSA value over
//! the canonical `SignedInfo`. That proves only that the certificate's key signed the
//! list.
//!
//! [`Tsl::parse_verified`] adds part B: the signer must be a C.TSL.SIG certificate the
//! configured TSL signer CA ([`TrustConfig::tsl_signer_anchor`]) issued, valid now; only
//! then is the list parsed, from the signed bytes. [`Tsl::parse_verified_prod`] does so
//! for production, [`Tsl::parse_verified_auto`] for whichever environment's embedded
//! TSL signer CA issued the signer.
//!
//! Not yet covered: the signer's OCSP status (part C), sequence number and grace period
//! (part D), an announced anchor and the path through roots.json (part E).

use core::fmt;

use bp256::BrainpoolP256r1;
use rustls_pki_types::alg_id;
use ti_xmldsig::{Document, ErrorKind, Limits};
use x509_cert::ext::pkix::KeyUsages;

use crate::algorithms::brainpool::BRAINPOOL_P256R1;
use crate::algorithms::{AlgorithmSet, find};
use crate::cert_type::TSL_SIGNING;
use crate::config::TEST_ONLY_MARKER;
use crate::time::Timestamp;
use crate::tsl::Tsl;
use crate::{Certificate, Tier, TrustConfig, oid};

/// The result codes of `spec/tsl-xmldsig` this module produces: the message short names
/// of gemSpec_PKI Tab_PKI_274, in lower case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TslCode {
    /// The input is not well-formed XML within the limits (1011).
    TslNotWellformed,
    /// The signature does not match the profile or does not verify (1013).
    XmlSignatureError,
    /// `KeyInfo` does not hold exactly one parsable certificate (1002).
    TslCertExtractionError,
    /// The signer is not issued by the TSL signer anchor, or its signature does not
    /// verify under it (1024).
    CertificateNotValidMath,
    /// The signer's AuthorityKeyIdentifier is not the anchor's SubjectKeyIdentifier
    /// (1023).
    AuthoritykeyidDifferent,
    /// The signer or the anchor is not valid at the validation time (1021).
    CertificateNotValidTime,
    /// The signer's KeyUsage is not exactly nonRepudiation (1016).
    WrongKeyusage,
    /// The signer's ExtendedKeyUsage is not exactly `id-tsl-kp-tslSigning` (1017).
    WrongExtendedkeyusage,
    /// The signer does not match the rest of C.TSL.SIG; `spec/tsl-xmldsig`'s own code,
    /// Tab_PKI_274 has none.
    TslSignerProfileViolation,
}

impl TslCode {
    /// Every code, in the order of the checks that produce them: for schemas and
    /// documentation that list them.
    pub const ALL: &[TslCode] = &[
        TslCode::TslNotWellformed,
        TslCode::XmlSignatureError,
        TslCode::TslCertExtractionError,
        TslCode::CertificateNotValidMath,
        TslCode::AuthoritykeyidDifferent,
        TslCode::CertificateNotValidTime,
        TslCode::WrongKeyusage,
        TslCode::WrongExtendedkeyusage,
        TslCode::TslSignerProfileViolation,
    ];

    /// The code's name, e.g. `xml_signature_error`.
    pub const fn as_str(self) -> &'static str {
        match self {
            TslCode::TslNotWellformed => "tsl_not_wellformed",
            TslCode::XmlSignatureError => "xml_signature_error",
            TslCode::TslCertExtractionError => "tsl_cert_extraction_error",
            TslCode::CertificateNotValidMath => "certificate_not_valid_math",
            TslCode::AuthoritykeyidDifferent => "authoritykeyid_different",
            TslCode::CertificateNotValidTime => "certificate_not_valid_time",
            TslCode::WrongKeyusage => "wrong_keyusage",
            TslCode::WrongExtendedkeyusage => "wrong_extendedkeyusage",
            TslCode::TslSignerProfileViolation => "tsl_signer_profile_violation",
        }
    }

    /// The message number of Tab_PKI_274; `None` for a code it does not define.
    pub const fn number(self) -> Option<u16> {
        match self {
            TslCode::TslNotWellformed => Some(1011),
            TslCode::XmlSignatureError => Some(1013),
            TslCode::TslCertExtractionError => Some(1002),
            TslCode::CertificateNotValidMath => Some(1024),
            TslCode::AuthoritykeyidDifferent => Some(1023),
            TslCode::CertificateNotValidTime => Some(1021),
            TslCode::WrongKeyusage => Some(1016),
            TslCode::WrongExtendedkeyusage => Some(1017),
            TslCode::TslSignerProfileViolation => None,
        }
    }
}

impl fmt::Display for TslCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected TSL: the result code, the rule of `spec/tsl-xmldsig` that failed, and what
/// exactly failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {rule}: {detail}")]
pub struct TslError {
    /// The result code.
    pub code: TslCode,
    /// The rule, e.g. `TSLSIG-018`.
    pub rule: &'static str,
    /// What failed, for humans; not stable.
    pub detail: String,
}

impl TslError {
    fn new(code: TslCode, rule: &'static str, detail: impl Into<String>) -> Self {
        TslError {
            code,
            rule,
            detail: detail.into(),
        }
    }

    fn signature(rule: &'static str, detail: impl Into<String>) -> Self {
        TslError::new(TslCode::XmlSignatureError, rule, detail)
    }
}

impl From<ti_xmldsig::Error> for TslError {
    fn from(e: ti_xmldsig::Error) -> Self {
        let code = match e.kind() {
            ErrorKind::NotWellFormed => TslCode::TslNotWellformed,
            ErrorKind::SignerCertificate => TslCode::TslCertExtractionError,
            _ => TslCode::XmlSignatureError,
        };
        TslError {
            code,
            rule: e.rule(),
            detail: e.detail().to_owned(),
        }
    }
}

/// A TSL whose signature verifies under the key of its signer certificate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignedTsl {
    /// The certificate in `KeyInfo`, which `CertDigest` and `X509SerialNumber` bind. Not
    /// yet authenticated.
    pub signer: Certificate,
    /// The canonical bytes of the signed content (TSLSIG-023): what to parse the TSL
    /// from, never the received bytes.
    pub content: Vec<u8>,
    /// `SigningTime` as written; informational (TSLSIG-021).
    pub signing_time: String,
}

/// Verifies the signature of the TSL `xml` with the algorithms of `algorithms`
/// (TSLSIG-001, 010 – 023).
///
/// # Errors
///
/// [`TslError`] with the code and the rule of the first check that failed.
pub fn verify(xml: &[u8], algorithms: &AlgorithmSet) -> Result<SignedTsl, TslError> {
    let xml_checked = Document::parse(xml, &Limits::TSL)?.verify_tsl_signature()?;

    let signer = Certificate::from_der(&xml_checked.signer_certificate).map_err(|e| TslError {
        code: TslCode::TslCertExtractionError,
        rule: "TSLSIG-022",
        detail: format!("signer certificate: {e}"),
    })?;
    if !serial_matches(&xml_checked.signer_serial, signer.serial()) {
        return Err(TslError::signature(
            "TSLSIG-020",
            format!(
                "X509SerialNumber {} is not the signer certificate's serial number",
                xml_checked.signer_serial
            ),
        ));
    }
    if signer.public_key_alg_id() != BRAINPOOL_P256R1.as_ref() {
        return Err(TslError::signature(
            "TSLSIG-012",
            "the signer key is not on brainpoolP256r1",
        ));
    }

    // XMLDSig writes r ‖ s; the algorithms take the DER ECDSA-Sig-Value.
    let signature = ecdsa::Signature::<BrainpoolP256r1>::from_slice(&xml_checked.signature)
        .map_err(|_| TslError::signature("TSLSIG-018", "r or s is out of range"))?
        .to_der();
    let algorithm = find(
        algorithms,
        BRAINPOOL_P256R1.as_ref(),
        alg_id::ECDSA_SHA256.as_ref(),
    )
    .ok_or_else(|| {
        TslError::signature(
            "TSLSIG-012",
            "the algorithm set has no ECDSA brainpoolP256r1 SHA-256",
        )
    })?;
    algorithm
        .verify_signature(
            signer.public_key(),
            &xml_checked.signed_info,
            signature.as_bytes(),
        )
        .map_err(|_| TslError::signature("TSLSIG-018", "the signature value does not verify"))?;

    Ok(SignedTsl {
        signer,
        content: xml_checked.content,
        signing_time: xml_checked.signing_time,
    })
}

/// A TSL whose signature verifies and whose signer the TSL signer anchor issued: the
/// list, parsed from the signed bytes, and the certificates it was verified with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VerifiedTsl {
    /// The list.
    pub tsl: Tsl,
    /// Production, if the anchor is not a TEST-ONLY CA.
    pub tier: Tier,
    /// The TSL signer CA that issued the signer.
    pub anchor: Certificate,
    /// The C.TSL.SIG certificate the list is signed with.
    pub signer: Certificate,
    /// `SigningTime` as written; informational (TSLSIG-021).
    pub signing_time: String,
}

impl Tsl {
    /// Verifies the TSL `xml` against `config` at `now` and parses it from the signed
    /// bytes: the signature (part A) and a signer issued by
    /// [`TrustConfig::tsl_signer_anchor`] (part B, TSLSIG-030 – 035), with the
    /// configuration's algorithms. Validity is checked without clock skew.
    ///
    /// # Errors
    ///
    /// [`TslError`] with the code and the rule of the first check that failed.
    pub fn parse_verified(
        xml: &[u8],
        config: &TrustConfig,
        now: Timestamp,
    ) -> Result<VerifiedTsl, TslError> {
        let anchor = Certificate::from_der(&config.tsl_signer_anchor).map_err(|e| {
            TslError::new(
                TslCode::CertificateNotValidMath,
                "TSLSIG-030",
                format!("TSL signer anchor: {e}"),
            )
        })?;
        let signed = verify(xml, &config.algorithms)?;
        check_signer(&signed.signer, &anchor, &config.algorithms, now)?;
        let tsl = Tsl::parse(&signed.content).map_err(|e| {
            TslError::new(
                TslCode::TslNotWellformed,
                "TSLSIG-023",
                format!("signed content: {e}"),
            )
        })?;
        let tier = if anchor.subject().to_string().contains(TEST_ONLY_MARKER) {
            Tier::NonProd
        } else {
            Tier::Prod
        };
        Ok(VerifiedTsl {
            tsl,
            tier,
            anchor,
            signer: signed.signer,
            signing_time: signed.signing_time,
        })
    }

    /// [`Tsl::parse_verified`] for production: GEM.TSL-CA3 and the production
    /// configuration's algorithms. A TSL of another environment fails.
    ///
    /// # Errors
    ///
    /// As [`Tsl::parse_verified`].
    pub fn parse_verified_prod(xml: &[u8], now: Timestamp) -> Result<VerifiedTsl, TslError> {
        Tsl::parse_verified(xml, &TrustConfig::preset_prod(), now)
    }

    /// [`Tsl::parse_verified`] for the environment whose embedded TSL signer CA issued the
    /// signer: GEM.TSL-CA3 (production) and, with the `dangerous-nonprod` feature,
    /// GEM.TSL-CA28 TEST-ONLY (reference, test, development). The result tells the
    /// [`Tier`] only: the non-production environments share one TSL signer CA.
    ///
    /// # Errors
    ///
    /// [`TslCode::CertificateNotValidMath`] if no embedded TSL signer CA has the signer's
    /// issuer name and key identifier; otherwise as [`Tsl::parse_verified`].
    pub fn parse_verified_auto(xml: &[u8], now: Timestamp) -> Result<VerifiedTsl, TslError> {
        let signed = verify(xml, crate::algorithms::DEFAULT)?;
        let config = embedded_configs()
            .into_iter()
            .find(|config| {
                Certificate::from_der(&config.tsl_signer_anchor).is_ok_and(|anchor| {
                    anchor.subject_der() == signed.signer.issuer_der()
                        && anchor.subject_key_id() == signed.signer.authority_key_id()
                })
            })
            .ok_or_else(|| {
                TslError::new(
                    TslCode::CertificateNotValidMath,
                    "TSLSIG-031",
                    format!(
                        "the signer's issuer {} is no embedded TSL signer CA",
                        signed.signer.issuer()
                    ),
                )
            })?;
        Tsl::parse_verified(xml, &config, now)
    }
}

/// The configurations whose TSL signer CAs [`Tsl::parse_verified_auto`] tries.
fn embedded_configs() -> Vec<TrustConfig> {
    #[cfg(feature = "dangerous-nonprod")]
    return vec![
        TrustConfig::preset_prod(),
        TrustConfig::preset(crate::Env::Test),
    ];
    #[cfg(not(feature = "dangerous-nonprod"))]
    vec![TrustConfig::preset_prod()]
}

/// Part B for the signer of a verified signature: issued by `anchor` (TSLSIG-031), both
/// valid at `now` (032), and C.TSL.SIG (033 – 035).
fn check_signer(
    signer: &Certificate,
    anchor: &Certificate,
    algorithms: &AlgorithmSet,
    now: Timestamp,
) -> Result<(), TslError> {
    let math =
        |detail: String| TslError::new(TslCode::CertificateNotValidMath, "TSLSIG-031", detail);
    if !anchor.is_ca() {
        return Err(math(format!(
            "TSL signer anchor {} is no CA",
            anchor.subject()
        )));
    }
    if signer.issuer_der() != anchor.subject_der() {
        return Err(math(format!(
            "the signer's issuer {} is not the TSL signer anchor {}",
            signer.issuer(),
            anchor.subject()
        )));
    }
    if signer.authority_key_id().is_none() || signer.authority_key_id() != anchor.subject_key_id() {
        return Err(TslError::new(
            TslCode::AuthoritykeyidDifferent,
            "TSLSIG-031",
            "the signer's AuthorityKeyIdentifier is not the anchor's SubjectKeyIdentifier",
        ));
    }
    // The profile's one signature algorithm first: a signer signed otherwise is a
    // profile violation, whether or not the algorithm set could verify it.
    if signer.signature_alg_id() != alg_id::ECDSA_SHA256.as_ref() {
        return Err(TslError::new(
            TslCode::TslSignerProfileViolation,
            "TSLSIG-035",
            "not C.TSL.SIG: the certificate is not signed with ecdsa-with-SHA256",
        ));
    }
    signer
        .verify_signed_by(anchor, algorithms)
        .map_err(|e| math(format!("the signer's certificate signature: {e}")))?;

    for (what, cert) in [("signer", signer), ("TSL signer anchor", anchor)] {
        if !cert.is_valid_at(now) {
            return Err(TslError::new(
                TslCode::CertificateNotValidTime,
                "TSLSIG-032",
                format!(
                    "{what} {} is valid from {} to {}, not at {now}",
                    cert.subject(),
                    cert.not_before(),
                    cert.not_after()
                ),
            ));
        }
    }

    let key_usage = signer.key_usage().map(|ku| ku.0);
    if key_usage != Some(KeyUsages::NonRepudiation.into()) {
        return Err(TslError::new(
            TslCode::WrongKeyusage,
            "TSLSIG-033",
            "KeyUsage is not exactly nonRepudiation",
        ));
    }
    if signer.ext_key_usage() != [TSL_SIGNING] {
        return Err(TslError::new(
            TslCode::WrongExtendedkeyusage,
            "TSLSIG-034",
            "ExtendedKeyUsage is not exactly id-tsl-kp-tslSigning",
        ));
    }

    let profile = |detail: &str| {
        TslError::new(
            TslCode::TslSignerProfileViolation,
            "TSLSIG-035",
            format!("not C.TSL.SIG: {detail}"),
        )
    };
    if !signer.policies().contains(&oid::POLICY_GEM_TSL_SIGNER) {
        return Err(profile("no oid_policy_gem_tsl_signer"));
    }
    if signer.basic_constraints().is_some_and(|bc| bc.ca) {
        return Err(profile("a CA certificate"));
    }
    if signer.ocsp_urls().is_empty() {
        return Err(profile("no OCSP URL in AuthorityInfoAccess"));
    }
    let key = signer.public_key();
    if signer.public_key_alg_id() != BRAINPOOL_P256R1.as_ref()
        || key.len() != 65
        || key.first() != Some(&0x04)
    {
        return Err(profile(
            "the key is not an uncompressed brainpoolP256r1 point",
        ));
    }
    Ok(())
}

/// Whether the decimal `written` (`X509SerialNumber`, an `xsd:integer`) is the serial
/// number whose big-endian two's-complement bytes are `serial`.
fn serial_matches(written: &str, serial: &[u8]) -> bool {
    // A serial number has at most 20 octets (RFC 5280 §4.1.2.2), so at most 49 digits;
    // the limit keeps the conversion linear in practice. Negative serials do not occur
    // here: ti-xmldsig accepts digits only.
    if written.len() > 64 || serial.first().is_some_and(|b| b & 0x80 != 0) {
        return false;
    }
    let mut value: Vec<u8> = Vec::new();
    for digit in written.bytes() {
        if !digit.is_ascii_digit() {
            return false;
        }
        let mut carry = digit - b'0';
        for byte in value.iter_mut().rev() {
            let [high, low] = (u16::from(*byte) * 10 + u16::from(carry)).to_be_bytes();
            *byte = low;
            carry = high;
        }
        if carry != 0 {
            value.insert(0, carry);
        }
    }
    let significant =
        |bytes: &[u8]| -> Vec<u8> { bytes.iter().copied().skip_while(|b| *b == 0).collect() };
    significant(&value) == significant(serial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::DEFAULT;

    fn real(name: &str) -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-xmldsig/testdata/tsl/real/"
        );
        std::fs::read(format!("{path}{name}")).unwrap()
    }

    #[test]
    fn tslsig_018_published_tsls_verify() {
        for name in [
            "pu-10333.xml",
            "pu-10334.xml",
            "tu-10687.xml",
            "tu-10713.xml",
        ] {
            let signed = verify(&real(name), DEFAULT).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                signed.signer.subject_cn().starts_with("TSL Signing Unit"),
                "{name}"
            );
            assert!(signed.content.starts_with(b"<TrustServiceStatusList "));
        }
    }

    #[test]
    fn tslsig_018_bundled_tsl_verifies() {
        let xml = include_bytes!("../tests/fixtures/tsl/ECC-RSA_TSL.xml");
        verify(xml, DEFAULT).unwrap();
    }

    /// A TSL whose XML still matches the profile and whose digests still hold, but whose
    /// `SignedInfo` changed (the free `Id` value of reference 2), fails at the ECDSA check.
    #[test]
    fn tslsig_018_changed_signed_info_fails_the_signature() {
        let xml = String::from_utf8(real("pu-10334.xml")).unwrap();
        let changed = xml.replacen(
            "<ds:Reference Id=\"Reference-SignedProperties-",
            "<ds:Reference Id=\"Reference-SignedPropertieS-",
            1,
        );
        assert_ne!(changed, xml);
        let e = verify(changed.as_bytes(), DEFAULT).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::XmlSignatureError, "TSLSIG-018"),
            "{e}"
        );
    }

    #[test]
    fn tslsig_012_needs_brainpool_in_the_algorithm_set() {
        let e = verify(&real("pu-10334.xml"), crate::algorithms::STANDARD).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::XmlSignatureError, "TSLSIG-012"),
            "{e}"
        );
    }

    #[test]
    fn codes_of_the_xml_layer() {
        let e = verify(b"<a>", DEFAULT).unwrap_err();
        assert_eq!((e.code, e.rule), (TslCode::TslNotWellformed, "TSLSIG-001"));
        assert_eq!(e.code.number(), Some(1011));

        let xml = String::from_utf8(real("pu-10334.xml")).unwrap();
        let changed = xml.replacen(
            "</ds:X509Data>",
            "</ds:X509Data><ds:KeyName>k</ds:KeyName>",
            1,
        );
        let e = verify(changed.as_bytes(), DEFAULT).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::TslCertExtractionError, "TSLSIG-022"),
            "{e}"
        );
        assert_eq!(e.code.number(), Some(1002));
    }

    #[test]
    fn tslsig_020_serial_numbers() {
        assert!(serial_matches("6", &[0x06]));
        assert!(serial_matches("0006", &[0x06]));
        assert!(serial_matches("128", &[0x00, 0x80]));
        assert!(serial_matches("262", &[0x01, 0x06]));
        assert!(!serial_matches("6", &[0x01, 0x06]));
        assert!(!serial_matches("7", &[0x06]));
        assert!(!serial_matches("128", &[0x80]));
        let big = "1461501637330902918203684832716283019655932542975"; // 2^160 − 1
        assert!(serial_matches(
            big,
            &[[0x00].as_slice(), &[0xff; 20]].concat()
        ));
        assert!(!serial_matches(&"9".repeat(65), &[0x01]));
    }

    fn at(rfc3339: &str) -> Timestamp {
        Timestamp::parse_rfc3339(rfc3339).unwrap()
    }

    macro_rules! signer_fixture {
        ($name:literal) => {
            crate::parse_pem_certificates(
                include_str!(concat!("../tests/pki/tsl-signer/", $name, ".pem")).as_bytes(),
            )
            .unwrap()
            .remove(0)
        };
    }

    #[track_caller]
    fn signer_fails(signer: &Certificate, code: TslCode, rule: &str) {
        let anchor = signer_fixture!("ca");
        let e = check_signer(signer, &anchor, DEFAULT, at("2027-01-01T00:00:00Z")).unwrap_err();
        assert_eq!((e.code, e.rule), (code, rule), "{e}");
    }

    #[test]
    fn tslsig_031_035_a_signer_as_gematik_issues_it_passes() {
        let anchor = signer_fixture!("ca");
        let signer = signer_fixture!("signer");
        check_signer(&signer, &anchor, DEFAULT, at("2027-01-01T00:00:00Z")).unwrap();
        // The published signers under their CAs.
        let ca3 = Certificate::from_der(crate::anchors::GEM_TSL_CA3).unwrap();
        let unit6 = crate::testing::typed("type-tsl-sig");
        check_signer(&unit6, &ca3, DEFAULT, at("2026-10-01T00:00:00Z")).unwrap();
    }

    #[test]
    fn tslsig_031_issuer_key_identifier_and_signature() {
        let ca3 = Certificate::from_der(crate::anchors::GEM_TSL_CA3).unwrap();
        let e = check_signer(
            &signer_fixture!("signer"),
            &ca3,
            DEFAULT,
            at("2027-01-01T00:00:00Z"),
        )
        .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidMath, "TSLSIG-031")
        );
        signer_fails(
            &signer_fixture!("signer-aki-different"),
            TslCode::AuthoritykeyidDifferent,
            "TSLSIG-031",
        );
        // A CA's name and key identifier, but not its key: only the signature tells.
        let anchor = signer_fixture!("ca-same-name");
        let e = check_signer(
            &signer_fixture!("signer-aki-different"),
            &anchor,
            crate::algorithms::STANDARD,
            at("2027-01-01T00:00:00Z"),
        )
        .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidMath, "TSLSIG-031"),
            "{e}"
        );
    }

    #[test]
    fn tslsig_032_validity_without_skew() {
        let anchor = signer_fixture!("ca");
        let signer = signer_fixture!("signer");
        check_signer(&signer, &anchor, DEFAULT, at("2026-01-01T00:00:00Z")).unwrap();
        check_signer(&signer, &anchor, DEFAULT, at("2031-01-01T00:00:00Z")).unwrap();
        for t in ["2025-12-31T23:59:59Z", "2031-01-01T00:00:01Z"] {
            let e = check_signer(&signer, &anchor, DEFAULT, at(t)).unwrap_err();
            assert_eq!(
                (e.code, e.rule),
                (TslCode::CertificateNotValidTime, "TSLSIG-032"),
                "{t}"
            );
        }
    }

    #[test]
    fn tslsig_033_034_key_usages_exactly() {
        signer_fails(
            &signer_fixture!("signer-ku-extra"),
            TslCode::WrongKeyusage,
            "TSLSIG-033",
        );
        signer_fails(
            &signer_fixture!("signer-eku-extra"),
            TslCode::WrongExtendedkeyusage,
            "TSLSIG-034",
        );
    }

    #[test]
    fn tslsig_035_the_rest_of_c_tsl_sig() {
        for signer in [
            signer_fixture!("signer-no-policy"),
            signer_fixture!("signer-ca"),
            signer_fixture!("signer-no-aia"),
            signer_fixture!("signer-compressed-key"),
            signer_fixture!("signer-p256"),
            signer_fixture!("signer-sha384"),
        ] {
            signer_fails(&signer, TslCode::TslSignerProfileViolation, "TSLSIG-035");
        }
    }

    #[test]
    fn tslsig_030_production_tsls_verify_for_production() {
        for (name, sequence) in [("pu-10333.xml", 10333), ("pu-10334.xml", 10334)] {
            let verified = Tsl::parse_verified_prod(&real(name), at("2026-10-03T00:00:00Z"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(verified.tier, Tier::Prod);
            assert_eq!(verified.tsl.sequence_number, sequence);
            assert_eq!(verified.anchor.subject_cn(), "GEM.TSL-CA3");
            assert_eq!(verified.signer.subject_cn(), "TSL Signing Unit 6");
            assert!(!verified.tsl.intermediate_cas().is_empty());
        }
    }

    #[test]
    fn tslsig_030_a_test_tsl_is_no_production_tsl() {
        let e = Tsl::parse_verified_prod(&real("tu-10713.xml"), at("2026-10-03T00:00:00Z"))
            .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidMath, "TSLSIG-031"),
            "{e}"
        );
    }

    #[test]
    fn tslsig_032_production_tsl_after_its_ca_expired() {
        let e = Tsl::parse_verified_prod(&real("pu-10334.xml"), at("2028-05-26T00:00:00Z"))
            .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidTime, "TSLSIG-032"),
            "{e}"
        );
    }

    #[test]
    fn tslsig_030_an_unusable_anchor_is_an_error() {
        let config = TrustConfig {
            tsl_signer_anchor: std::borrow::Cow::Borrowed(b"not a certificate"),
            ..TrustConfig::preset_prod()
        };
        let e = Tsl::parse_verified(&real("pu-10334.xml"), &config, at("2026-10-03T00:00:00Z"))
            .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidMath, "TSLSIG-030")
        );
    }

    #[test]
    fn auto_detects_production() {
        let verified =
            Tsl::parse_verified_auto(&real("pu-10334.xml"), at("2026-10-03T00:00:00Z")).unwrap();
        assert_eq!(verified.tier, Tier::Prod);
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn test_tsls_verify_for_non_production() {
        let now = at("2026-10-03T00:00:00Z");
        for name in ["tu-10687.xml", "tu-10713.xml"] {
            let config = TrustConfig::preset(crate::Env::Test);
            let verified = Tsl::parse_verified(&real(name), &config, now).unwrap();
            assert_eq!(verified.tier, Tier::NonProd);
            assert_eq!(verified.anchor.subject_cn(), "GEM.TSL-CA28 TEST-ONLY");
            let auto = Tsl::parse_verified_auto(&real(name), now).unwrap();
            assert_eq!(auto.tier, Tier::NonProd);
            assert_eq!(auto.tsl.sequence_number, verified.tsl.sequence_number);
        }
        // And a production TSL under the non-production anchor fails.
        let e = Tsl::parse_verified(
            &real("pu-10334.xml"),
            &TrustConfig::preset(crate::Env::Ref),
            now,
        )
        .unwrap_err();
        assert_eq!(e.code, TslCode::CertificateNotValidMath);
    }

    #[cfg(not(feature = "dangerous-nonprod"))]
    #[test]
    fn without_nonprod_material_a_test_tsl_is_not_recognised() {
        let e = Tsl::parse_verified_auto(&real("tu-10713.xml"), at("2026-10-03T00:00:00Z"))
            .unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::CertificateNotValidMath, "TSLSIG-031"),
            "{e}"
        );
    }
}
