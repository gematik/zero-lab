//! The signature of a TSL, its signer and the rules of an update (`spec/tsl-xmldsig`,
//! parts A to D).
//!
//! [`verify`] is part A: `ti-xmldsig` checks the XML against the fixed XMLDSig/XAdES
//! profile and the reference digests; this module parses the signer certificate, binds
//! it by serial number, requires a brainpoolP256r1 key and verifies the ECDSA value over
//! the canonical `SignedInfo`. That proves only that the certificate's key signed the
//! list.
//!
//! [`Tsl::parse_verified`] adds part B: the signer must be a C.TSL.SIG certificate the
//! configured TSL signer CA ([`TrustConfig::tsl_signer_anchor`]) issued, valid now; only
//! then is the list parsed, from the signed bytes, skipping what cannot be processed.
//! A list past its `NextUpdate` and the grace period is rejected, within the grace
//! period it carries a warning (part D). [`Tsl::parse_verified_prod`] does so for
//! production, [`Tsl::parse_verified_auto`] for whichever environment's embedded TSL
//! signer CA issued the signer.
//!
//! [`VerifiedTsl::check_signer_status`] is part C, with a network: the signer's OCSP
//! status at the responder in its certificate, which only its CA or a responder that CA
//! certified may answer. Without it the result carries the warning
//! [`TslCode::NoOcspCheck`]. [`VerifiedTsl::check_sequence`] compares the list with the
//! one stored before (part D).
//!
//! Not yet covered: an announced anchor and the path through roots.json (part E).

use core::fmt;

#[cfg(feature = "brainpool")]
use bp256::BrainpoolP256r1;
#[cfg(feature = "brainpool")]
use rustls_pki_types::alg_id;
use ti_xmldsig::ErrorKind;
#[cfg(feature = "brainpool")]
use ti_xmldsig::{Document, Limits};
#[cfg(feature = "brainpool")]
use x509_cert::ext::pkix::KeyUsages;

#[cfg(feature = "brainpool")]
use crate::algorithms::brainpool::BRAINPOOL_P256R1;
#[cfg(feature = "brainpool")]
use crate::algorithms::{AlgorithmSet, find};
#[cfg(feature = "brainpool")]
use crate::cert_type::TSL_SIGNING;
#[cfg(feature = "brainpool")]
use crate::config::TEST_ONLY_MARKER;
use crate::error::{ErrorCode, ValidationError};
use crate::ocsp::{ResponseDefect, UNKNOWN_STATUS};
use crate::revocation::{RevocationChecker, RevocationResult, RevocationStatus};
#[cfg(feature = "brainpool")]
use crate::time::Timestamp;
use crate::tsl::Tsl;
use crate::{Certificate, Tier, TrustStore};
#[cfg(feature = "brainpool")]
use crate::{TrustConfig, oid};

/// The lowest sequence number of a TSL(ECC-RSA) (A_17685).
pub const MIN_SEQUENCE_NUMBER: u64 = 10_000;

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
    /// Warning: the signer's OCSP status was not queried, for want of a network (1039).
    NoOcspCheck,
    /// The OCSP responder signed with a key that does not verify or is not authorized
    /// for the signer's CA (1031).
    OcspSignatureError,
    /// The OCSP response lacks the certHash extension (1040).
    CerthashExtensionMissing,
    /// The OCSP certHash is not the signer certificate's (1041).
    CerthashMismatch,
    /// The responder does not know the signer (1044).
    CertUnknown,
    /// The signer is revoked (1047).
    CertRevoked,
    /// The responder answered with an OCSP status error, also after repetition (1058).
    OcspStatusError,
    /// The responder could not be reached, or its answer does not fit the request or the
    /// time (1029).
    OcspCheckRevocationError,
    /// The list's `Id` and sequence number do not follow the stored ones, or the sequence
    /// number is below 10000 (1007).
    TslIdIncorrect,
    /// Warning: the list is past its `NextUpdate`, within the grace period (1008).
    ValidityWarning1,
    /// The list is past its `NextUpdate` and the grace period; nothing from it may be
    /// used (1009, a warning in Tab_PKI_274 that stops the use of the list).
    ValidityWarning2,
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
        TslCode::NoOcspCheck,
        TslCode::OcspSignatureError,
        TslCode::CerthashExtensionMissing,
        TslCode::CerthashMismatch,
        TslCode::CertUnknown,
        TslCode::CertRevoked,
        TslCode::OcspStatusError,
        TslCode::OcspCheckRevocationError,
        TslCode::TslIdIncorrect,
        TslCode::ValidityWarning1,
        TslCode::ValidityWarning2,
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
            TslCode::NoOcspCheck => "no_ocsp_check",
            TslCode::OcspSignatureError => "ocsp_signature_error",
            TslCode::CerthashExtensionMissing => "certhash_extension_missing",
            TslCode::CerthashMismatch => "certhash_mismatch",
            TslCode::CertUnknown => "cert_unknown",
            TslCode::CertRevoked => "cert_revoked",
            TslCode::OcspStatusError => "ocsp_status_error",
            TslCode::OcspCheckRevocationError => "ocsp_check_revocation_error",
            TslCode::TslIdIncorrect => "tsl_id_incorrect",
            TslCode::ValidityWarning1 => "validity_warning_1",
            TslCode::ValidityWarning2 => "validity_warning_2",
        }
    }

    /// Whether the code is a warning, which leaves the list usable.
    pub const fn is_warning(self) -> bool {
        matches!(self, TslCode::NoOcspCheck | TslCode::ValidityWarning1)
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
            TslCode::NoOcspCheck => Some(1039),
            TslCode::OcspSignatureError => Some(1031),
            TslCode::CerthashExtensionMissing => Some(1040),
            TslCode::CerthashMismatch => Some(1041),
            TslCode::CertUnknown => Some(1044),
            TslCode::CertRevoked => Some(1047),
            TslCode::OcspStatusError => Some(1058),
            TslCode::OcspCheckRevocationError => Some(1029),
            TslCode::TslIdIncorrect => Some(1007),
            TslCode::ValidityWarning1 => Some(1008),
            TslCode::ValidityWarning2 => Some(1009),
        }
    }
}

impl fmt::Display for TslCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected TSL, or a warning about a usable one: the result code, the rule of
/// `spec/tsl-xmldsig`, and what exactly happened.
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

    #[cfg(feature = "brainpool")]
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

#[cfg(feature = "brainpool")]
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
    /// What leaves the list usable but deserves attention: [`TslCode::NoOcspCheck`] until
    /// [`check_signer_status`](Self::check_signer_status) succeeded,
    /// [`TslCode::ValidityWarning1`] within the grace period.
    pub warnings: Vec<TslError>,
    /// The signer's OCSP result, once [`check_signer_status`](Self::check_signer_status)
    /// succeeded.
    pub signer_status: Option<RevocationResult>,
}

/// What is kept of a TSL between updates to judge the next one (TSLSIG-053). Persist it:
/// it must survive restarts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TslState {
    /// The root element's `Id`.
    pub id: String,
    /// `TSLSequenceNumber`.
    pub sequence_number: u64,
}

impl TslState {
    /// The state of `tsl`.
    pub fn of(tsl: &Tsl) -> Self {
        TslState {
            id: tsl.id.clone(),
            sequence_number: tsl.sequence_number,
        }
    }
}

/// How a verified list relates to the stored one (TSLSIG-053).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sequence {
    /// A newer list, or the first one: update.
    Newer,
    /// The stored list again: no update, no error.
    Same,
}

impl VerifiedTsl {
    /// The signer's OCSP status (part C, TSLSIG-040 – 042), from `checker`, normally an
    /// [`OcspChecker`](crate::ocsp::OcspChecker) over a network transport: asked at the
    /// responder named in the signer certificate, with the TSL signer CA as issuer. Only
    /// that CA or a responder it certified may answer (RFC 6960): no trust store is
    /// offered for delegates of the same provider. `good` removes the
    /// [`TslCode::NoOcspCheck`] warning.
    ///
    /// # Errors
    ///
    /// [`TslError`] with the code of TSLSIG-041 or 042; the list must not be used.
    pub async fn check_signer_status(
        &mut self,
        checker: &impl RevocationChecker,
    ) -> Result<(), TslError> {
        let result = checker
            .check(&self.signer, &self.anchor, &TrustStore::new([]))
            .await
            .map_err(|e| status_error(&e))?;
        let detail = |what: &str| format!("{what} ({})", result.responder_url);
        match result.status {
            RevocationStatus::Good => {}
            RevocationStatus::Revoked => {
                return Err(TslError::new(
                    TslCode::CertRevoked,
                    "TSLSIG-041",
                    detail(&format!("the signer is revoked: {}", result.reason)),
                ));
            }
            RevocationStatus::Unknown if result.reason == UNKNOWN_STATUS => {
                return Err(TslError::new(
                    TslCode::CertUnknown,
                    "TSLSIG-041",
                    detail("the responder does not know the signer"),
                ));
            }
            RevocationStatus::Unknown => {
                return Err(TslError::new(
                    TslCode::OcspCheckRevocationError,
                    "TSLSIG-042",
                    detail(&result.reason),
                ));
            }
        }
        self.warnings.retain(|w| w.code != TslCode::NoOcspCheck);
        self.signer_status = Some(result);
        Ok(())
    }

    /// Compares the list with the `stored` one (TSLSIG-053): none stored, or another
    /// `Id` and a greater sequence number, is [`Sequence::Newer`]; the same `Id` and
    /// sequence number is [`Sequence::Same`].
    ///
    /// # Errors
    ///
    /// [`TslCode::TslIdIncorrect`] for a sequence number below [`MIN_SEQUENCE_NUMBER`] and
    /// for anything else: an older list, the same number under another `Id`, or the same
    /// `Id` under another number.
    pub fn check_sequence(&self, stored: Option<&TslState>) -> Result<Sequence, TslError> {
        let (id, number) = (&self.tsl.id, self.tsl.sequence_number);
        let incorrect =
            |detail: String| TslError::new(TslCode::TslIdIncorrect, "TSLSIG-053", detail);
        if number < MIN_SEQUENCE_NUMBER {
            return Err(incorrect(format!(
                "sequence number {number} is below {MIN_SEQUENCE_NUMBER}"
            )));
        }
        let Some(stored) = stored else {
            return Ok(Sequence::Newer);
        };
        if *id == stored.id && number == stored.sequence_number {
            Ok(Sequence::Same)
        } else if *id != stored.id && number > stored.sequence_number {
            Ok(Sequence::Newer)
        } else {
            Err(incorrect(format!(
                "Id {id:?} with sequence number {number} does not follow Id {:?} with {}",
                stored.id, stored.sequence_number
            )))
        }
    }
}

/// TSLSIG-040 – 042 for a check that failed, by what exactly failed.
fn status_error(error: &ValidationError) -> TslError {
    let (code, rule) = match (error.code, error.defect) {
        (ErrorCode::OcspResponseInvalid, Some(ResponseDefect::CertHashMissing)) => {
            (TslCode::CerthashExtensionMissing, "TSLSIG-041")
        }
        (ErrorCode::OcspResponseInvalid, Some(ResponseDefect::CertHashMismatch)) => {
            (TslCode::CerthashMismatch, "TSLSIG-041")
        }
        (ErrorCode::OcspResponseInvalid, Some(ResponseDefect::Signature))
        | (ErrorCode::OcspResponderUntrusted, _) => (TslCode::OcspSignatureError, "TSLSIG-040"),
        (ErrorCode::OcspUnavailable, _) if !unreachable(error) => {
            (TslCode::OcspStatusError, "TSLSIG-042")
        }
        _ => (TslCode::OcspCheckRevocationError, "TSLSIG-042"),
    };
    TslError::new(code, rule, error.message.clone())
}

/// Whether the responder could not be reached at all, as opposed to answering with an
/// error status.
fn unreachable(error: &ValidationError) -> bool {
    #[cfg(feature = "load")]
    return error.cause.as_deref().is_some_and(|cause| {
        cause
            .downcast_ref::<crate::load::TransportError>()
            .is_some()
    });
    #[cfg(not(feature = "load"))]
    {
        let _ = error;
        false
    }
}

#[cfg(feature = "brainpool")]
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
        let tsl = Tsl::parse_with(&signed.content, true).map_err(|e| {
            TslError::new(
                TslCode::TslNotWellformed,
                "TSLSIG-023",
                format!("signed content: {e}"),
            )
        })?;
        let mut warnings = Vec::new();
        if let Some(next_update) = tsl.next_update
            && now >= next_update
        {
            let past = format!("NextUpdate {next_update} has passed at {now}");
            if now >= next_update + config.tsl_grace_period {
                return Err(TslError::new(
                    TslCode::ValidityWarning2,
                    "TSLSIG-054",
                    format!(
                        "{past}, beyond the grace period of {} s",
                        config.tsl_grace_period.as_secs()
                    ),
                ));
            }
            warnings.push(TslError::new(TslCode::ValidityWarning1, "TSLSIG-054", past));
        }
        warnings.push(TslError::new(
            TslCode::NoOcspCheck,
            "TSLSIG-043",
            "the signer's OCSP status was not queried",
        ));
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
            warnings,
            signer_status: None,
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
        Tsl::parse_verified(xml, &embedded_config_for(xml)?, now)
    }
}

#[cfg(feature = "brainpool")]
/// The preset whose embedded TSL signer CA has the name and key identifier of the issuer
/// of `xml`'s signer, as [`Tsl::parse_verified_auto`] picks it; a caller adjusts it, e.g.
/// [`TrustConfig::tsl_grace_period`], before [`Tsl::parse_verified`]. Only the signature
/// is verified here.
///
/// # Errors
///
/// As [`verify`], and [`TslCode::CertificateNotValidMath`] if no embedded TSL signer CA
/// fits.
pub fn embedded_config_for(xml: &[u8]) -> Result<TrustConfig, TslError> {
    let signed = verify(xml, crate::algorithms::DEFAULT)?;
    embedded_configs()
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
        })
}

#[cfg(feature = "brainpool")]
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

#[cfg(feature = "brainpool")]
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

#[cfg(feature = "brainpool")]
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

#[cfg(all(test, feature = "brainpool"))]
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
        // Each within its own validity: tu-10687 expired on 2026-07-02.
        for (name, now) in [
            ("tu-10687.xml", at("2026-06-03T00:00:00Z")),
            ("tu-10713.xml", at("2026-10-03T00:00:00Z")),
        ] {
            let config = TrustConfig::preset(crate::Env::Test);
            let verified = Tsl::parse_verified(&real(name), &config, now).unwrap();
            assert_eq!(verified.tier, Tier::NonProd);
            assert_eq!(verified.anchor.subject_cn(), "GEM.TSL-CA28 TEST-ONLY");
            let auto = Tsl::parse_verified_auto(&real(name), now).unwrap();
            assert_eq!(auto.tier, Tier::NonProd);
            assert_eq!(auto.tsl.sequence_number, verified.tsl.sequence_number);
        }
        // And a production TSL under the non-production anchor fails.
        let now = at("2026-10-03T00:00:00Z");
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

    /// pu-10334: issued 2026-09-27T23:00:07Z, NextUpdate 2026-10-27T23:00:07Z.
    fn pu_10334(now: &str, grace_days: u64) -> Result<VerifiedTsl, TslError> {
        let config = TrustConfig {
            tsl_grace_period: core::time::Duration::from_hours(grace_days * 24),
            ..TrustConfig::preset_prod()
        };
        Tsl::parse_verified(&real("pu-10334.xml"), &config, at(now))
    }

    fn codes(warnings: &[TslError]) -> Vec<TslCode> {
        warnings.iter().map(|w| w.code).collect()
    }

    #[test]
    fn tslsig_054_next_update_and_grace_period() {
        let before = pu_10334("2026-10-27T23:00:06Z", 0).unwrap();
        assert_eq!(codes(&before.warnings), [TslCode::NoOcspCheck]);

        let e = pu_10334("2026-10-27T23:00:07Z", 0).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::ValidityWarning2, "TSLSIG-054"),
            "{e}"
        );
        assert!(!e.code.is_warning());

        let within = pu_10334("2026-11-01T00:00:00Z", 7).unwrap();
        assert_eq!(
            codes(&within.warnings),
            [TslCode::ValidityWarning1, TslCode::NoOcspCheck]
        );
        assert!(TslCode::ValidityWarning1.is_warning());
        let e = pu_10334("2026-11-03T23:00:07Z", 7).unwrap_err();
        assert_eq!(e.code, TslCode::ValidityWarning2);
    }

    #[test]
    fn tslsig_052_the_published_lists_skip_nothing() {
        let verified = pu_10334("2026-10-03T00:00:00Z", 0).unwrap();
        assert!(verified.tsl.skipped.is_empty());
        assert_eq!(verified.tsl.id, "ID31033420260927230007Z");
    }

    #[test]
    fn tslsig_053_sequence() {
        let mut verified = pu_10334("2026-10-03T00:00:00Z", 0).unwrap();
        let state = |id: &str, sequence_number| TslState {
            id: id.to_owned(),
            sequence_number,
        };
        let previous = TslState::of(
            &Tsl::parse_verified_prod(&real("pu-10333.xml"), at("2026-10-03T00:00:00Z"))
                .unwrap()
                .tsl,
        );
        assert_eq!(verified.check_sequence(None), Ok(Sequence::Newer));
        assert_eq!(
            verified.check_sequence(Some(&previous)),
            Ok(Sequence::Newer)
        );
        let current = TslState::of(&verified.tsl);
        assert_eq!(verified.check_sequence(Some(&current)), Ok(Sequence::Same));
        for stored in [
            state("ID31033420260927230007Z", 10333),
            state("other", 10334),
            state("other", 10335),
        ] {
            let e = verified.check_sequence(Some(&stored)).unwrap_err();
            assert_eq!(
                (e.code, e.rule),
                (TslCode::TslIdIncorrect, "TSLSIG-053"),
                "{stored:?}"
            );
        }
        verified.tsl.sequence_number = 9999;
        let e = verified.check_sequence(None).unwrap_err();
        assert_eq!(e.code, TslCode::TslIdIncorrect);
    }

    /// Answers every check with one scripted outcome.
    struct Scripted(Result<RevocationResult, ValidationError>);

    impl RevocationChecker for Scripted {
        async fn check(
            &self,
            _cert: &Certificate,
            _issuer: &Certificate,
            store: &TrustStore,
        ) -> Result<RevocationResult, ValidationError> {
            assert!(store.is_empty(), "RFC 6960 only: no store for delegates");
            self.0.clone()
        }
    }

    fn result(status: RevocationStatus, reason: &str) -> RevocationResult {
        let mut result = RevocationResult::unknown(at("2026-10-03T00:00:00Z"), reason);
        result.status = status;
        result.responder_url = "http://ocsp.tsl.ti-dienste.de/ocsp".into();
        result
    }

    fn status(outcome: Result<RevocationResult, ValidationError>) -> Result<VerifiedTsl, TslError> {
        let mut verified = pu_10334("2026-10-03T00:00:00Z", 0).unwrap();
        futures_lite::future::block_on(verified.check_signer_status(&Scripted(outcome)))?;
        Ok(verified)
    }

    #[test]
    fn tslsig_040_043_a_good_status_lifts_the_warning() {
        let verified = status(Ok(result(RevocationStatus::Good, ""))).unwrap();
        assert!(verified.warnings.is_empty());
        assert_eq!(
            verified.signer_status.map(|r| r.status),
            Some(RevocationStatus::Good)
        );
    }

    #[test]
    fn tslsig_041_042_what_stops_the_update() {
        let invalid = |defect| {
            Err(ValidationError::new(ErrorCode::OcspResponseInvalid, "x").with_defect(defect))
        };
        let unavailable = || ValidationError::new(ErrorCode::OcspUnavailable, "tryLater");
        let cases = [
            (
                Ok(result(RevocationStatus::Revoked, "keyCompromise")),
                TslCode::CertRevoked,
            ),
            (
                Ok(result(RevocationStatus::Unknown, UNKNOWN_STATUS)),
                TslCode::CertUnknown,
            ),
            (
                Ok(result(
                    RevocationStatus::Unknown,
                    "OCSP producedAt lies 60 s in the future",
                )),
                TslCode::OcspCheckRevocationError,
            ),
            (
                invalid(ResponseDefect::CertHashMissing),
                TslCode::CerthashExtensionMissing,
            ),
            (
                invalid(ResponseDefect::CertHashMismatch),
                TslCode::CerthashMismatch,
            ),
            (
                invalid(ResponseDefect::Signature),
                TslCode::OcspSignatureError,
            ),
            (
                invalid(ResponseDefect::WrongCertificate),
                TslCode::OcspCheckRevocationError,
            ),
            (
                Err(ValidationError::new(ErrorCode::OcspResponderUntrusted, "x")),
                TslCode::OcspSignatureError,
            ),
            (Err(unavailable()), TslCode::OcspStatusError),
        ];
        for (outcome, code) in cases {
            let e = status(outcome).unwrap_err();
            assert_eq!(e.code, code, "{e}");
            assert!(!e.code.is_warning());
        }
    }

    #[cfg(feature = "load")]
    #[test]
    fn tslsig_042_an_unreachable_responder() {
        let unreachable = ValidationError::new(ErrorCode::OcspUnavailable, "unreachable")
            .with_cause(crate::load::TransportError {
                kind: crate::load::TransportErrorKind::Other,
                message: "connection refused".into(),
                retryable: true,
            });
        let e = status(Err(unreachable)).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::OcspCheckRevocationError, "TSLSIG-042")
        );
    }
}
