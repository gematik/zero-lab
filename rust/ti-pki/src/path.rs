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

//! Path validation of a built chain per RFC 5280 §6, plus the end-entity
//! checks a profile requires. Every certificate must be within its validity
//! window and carry no critical extension outside [`PROCESSED_EXTENSIONS`];
//! every CA must be marked as such, allow certificate signing and
//! respect its path-length constraint; each link's signature is verified
//! under its issuer's key, for ECDSA on Brainpool and NIST curves and for RSA.

use core::time::Duration;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER,
    ID_PE_AUTHORITY_INFO_ACCESS,
};

use crate::algorithms::AlgorithmSet;
use crate::checks::CertificateCheck;
use crate::error::{ErrorCode, ValidationError, ValidationWarning};
use crate::time::Timestamp;
use crate::validate::{CertResult, ChainPosition, ValidationResult};
use crate::{Certificate, Error};

/// PATH-004: the extensions this crate processes, and so the only ones a certificate may
/// mark critical (RFC 5280 §4.2). Real TI certificates mark basicConstraints and keyUsage
/// critical, a few also extendedKeyUsage. Name constraints and policy constraints are
/// not implemented, so a CA marking them critical is rejected rather than half-checked.
pub const PROCESSED_EXTENSIONS: &[ObjectIdentifier] = &[
    ID_CE_BASIC_CONSTRAINTS,
    ID_CE_KEY_USAGE,
    ID_CE_EXT_KEY_USAGE,
    ID_CE_CERTIFICATE_POLICIES,
    ID_CE_SUBJECT_ALT_NAME,
    ID_CE_AUTHORITY_KEY_IDENTIFIER,
    ID_CE_SUBJECT_KEY_IDENTIFIER,
    ID_PE_AUTHORITY_INFO_ACCESS,
    crate::oid::ADMISSION_EXTENSION,
];

/// When a CA's validity counts (gemKPT_PKI_TIP 2.4). The end entity is checked at the
/// reference time under either (gemSpec_PKI TUC_PKI_002).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValidityModel {
    /// The PKIX shell model (2.4.1): every certificate of the chain valid at the
    /// reference time. For components (devices, services) and the eGK's nonQES
    /// certificates.
    #[default]
    Shell,
    /// The Kompromissmodell (2.4.2): each CA valid when it issued the certificate below
    /// it. For every nonQES certificate of the HBA and the SMC-B; a CA expired since is
    /// a warning ([`ErrorCode::CaExpired`]), as the TSL keeps such CAs in
    /// accord (gemSpec_PKI Tab_PKI_271).
    Compromise,
}

impl ValidityModel {
    /// PATH-003: the model gemKPT_PKI_TIP 2.4 assigns to `cert_type`.
    pub const fn for_type(cert_type: crate::CertificateType) -> Self {
        use crate::CertificateType as T;
        match cert_type {
            T::HpAut | T::HpEnc | T::HciAut | T::HciEnc | T::HciOsig => ValidityModel::Compromise,
            _ => ValidityModel::Shell,
        }
    }
}

/// What [`validate_path`] checks against.
#[derive(Clone, Copy)]
pub struct PathOptions<'a> {
    /// The instant validity is checked at; a past signature time for historical
    /// validation.
    pub now: Timestamp,
    /// The algorithms signatures may be verified with.
    pub algorithms: &'a AlgorithmSet,
    /// How far `now` may lie outside a validity window before it counts: the skew
    /// between the issuer's clock and ours ([`TrustConfig::max_clock_skew`]).
    ///
    /// [`TrustConfig::max_clock_skew`]: crate::TrustConfig::max_clock_skew
    pub max_clock_skew: Duration,
    /// Checks run on the end entity after the RFC 5280 checks.
    pub ee_checks: &'a [CertificateCheck],
    /// When the CAs' validity counts.
    pub model: ValidityModel,
}

/// Validates `chain` (end entity first, root last, as [`build_chain`] returns it)
/// against RFC 5280 §6 and the end-entity checks.
///
/// PATH-002: the end entity must be valid at `now`; each CA at `now` under the shell model, or
/// when it issued the certificate below under the Kompromissmodell. Every certificate
/// but the root may mark only [`PROCESSED_EXTENSIONS`] critical (PATH-004); the root is
/// the trust anchor, whose extensions RFC 5280 leaves to the relying party. Every CA below the end entity must be
/// marked as a CA, must allow certificate signing if it restricts key usage, and must
/// not have more intermediates beneath it than its path length constraint allows
/// (PATH-005). Every link's signature must verify under the next certificate's key
/// (PATH-006). All findings are
/// collected; the result is valid only without any.
///
/// # Errors
///
/// [`Error::Malformed`] for a chain shorter than end entity plus root.
///
/// [`build_chain`]: crate::chain::build_chain
pub fn validate_path(
    chain: &[Certificate],
    options: &PathOptions<'_>,
) -> Result<ValidationResult, Error> {
    if chain.len() < 2 {
        return Err(Error::Malformed {
            what: "chain",
            reason: format!(
                "needs at least an end entity and a root, got {} certificate(s)",
                chain.len()
            ),
        });
    }
    let positions: Vec<ChainPosition> = (0..chain.len())
        .map(|i| position_of(i, chain.len()))
        .collect();
    let mut result = ValidationResult {
        valid: true,
        chain: chain.to_vec(),
        cert_results: chain
            .iter()
            .zip(&positions)
            .map(|(cert, position)| CertResult {
                subject: cert.subject_cn().to_owned(),
                position: *position,
                revocation: None,
            })
            .collect(),
        positions,
        ..ValidationResult::default()
    };

    for (i, cert) in chain.iter().enumerate() {
        let issued = i
            .checked_sub(1)
            .and_then(|below| chain.get(below))
            .filter(|_| options.model == ValidityModel::Compromise);
        match issued {
            Some(below) => check_issuer_validity(cert, below, options, &mut result),
            None => {
                if let Err(e) = check_validity(cert, options.now, options.max_clock_skew) {
                    result.add_error(e);
                }
            }
        }
        if i + 1 < chain.len() {
            for extension in cert
                .critical_extensions()
                .filter(|oid| !PROCESSED_EXTENSIONS.contains(oid))
            {
                result.add_error(
                    ValidationError::new(
                        ErrorCode::UnrecognizedCriticalExtension,
                        format!(
                            "critical extension {} is not processed (RFC 5280 §4.2)",
                            crate::oid::format(&extension)
                        ),
                    )
                    .with_subject(cert.subject_cn()),
                );
            }
        }
        if i > 0
            && let Err(e) = check_ca_constraints(cert, i.saturating_sub(1))
        {
            result.add_error(e);
        }
        if let Some(issuer) = chain.get(i + 1)
            && let Err(e) = cert.verify_signed_by(issuer, options.algorithms)
        {
            result.add_error(
                ValidationError::new(
                    ErrorCode::SignatureInvalid,
                    "chain signature verification failed",
                )
                .with_subject(cert.subject_cn())
                .with_cause(e),
            );
        }
        if i == 0 {
            for check in options.ee_checks {
                if let Err(mut e) = check(cert) {
                    if e.subject.is_empty() {
                        cert.subject_cn().clone_into(&mut e.subject);
                    }
                    result.add_error(e);
                }
            }
        }
    }
    Ok(result)
}

fn position_of(i: usize, len: usize) -> ChainPosition {
    if i == 0 {
        ChainPosition::EndEntity
    } else if i == len - 1 {
        ChainPosition::Root
    } else {
        ChainPosition::SubCa
    }
}

/// The Kompromissmodell for the CA `cert`, which issued `below`: valid at `below`'s
/// notBefore, or an error; expired at `now` although valid then, a warning.
fn check_issuer_validity(
    cert: &Certificate,
    below: &Certificate,
    options: &PathOptions<'_>,
    result: &mut ValidationResult,
) {
    if let Err(mut e) = check_validity(cert, below.not_before(), options.max_clock_skew) {
        e.message = format!(
            "{} when it issued {:?} (Kompromissmodell)",
            e.message,
            below.subject_cn()
        );
        result.add_error(e);
    } else if check_validity(cert, options.now, options.max_clock_skew).is_err() {
        result.warnings.push(
            ValidationWarning::new(
                ErrorCode::CaExpired,
                format!(
                    "expired (notAfter={}); {:?}, which it issued, is accepted under the \
                     Kompromissmodell for HBA and SMC-B, as the CA was valid when it issued it",
                    cert.not_after(),
                    below.subject_cn()
                ),
            )
            .with_subject(cert.subject_cn()),
        );
    }
}

fn check_validity(
    cert: &Certificate,
    now: Timestamp,
    skew: Duration,
) -> Result<(), ValidationError> {
    let skew = skew.as_secs();
    if now.0.saturating_add(skew) < cert.not_before().0 {
        return Err(ValidationError::new(
            ErrorCode::NotYetValid,
            format!("notBefore={}, now={now}", cert.not_before()),
        )
        .with_subject(cert.subject_cn()));
    }
    if now.0.saturating_sub(skew) > cert.not_after().0 {
        return Err(ValidationError::new(
            ErrorCode::Expired,
            format!("notAfter={}, now={now}", cert.not_after()),
        )
        .with_subject(cert.subject_cn()));
    }
    Ok(())
}

/// `intermediates_below`: CAs between this certificate and the end entity.
fn check_ca_constraints(
    cert: &Certificate,
    intermediates_below: usize,
) -> Result<(), ValidationError> {
    let fail = |code, message: String| {
        Err(ValidationError::new(code, message).with_subject(cert.subject_cn()))
    };
    if !cert.is_ca() {
        return fail(
            ErrorCode::ChainIncomplete,
            "non-root, non-EE certificate is not marked CA".into(),
        );
    }
    if let Some(ku) = cert.key_usage()
        && !ku.0.contains(x509_cert::ext::pkix::KeyUsages::KeyCertSign)
    {
        return fail(
            ErrorCode::KeyUsageMismatch,
            "CA certificate missing KeyUsageCertSign".into(),
        );
    }
    if let Some(allowed) = cert
        .basic_constraints()
        .and_then(|bc| bc.path_len_constraint)
        && intermediates_below > usize::from(allowed)
    {
        return fail(
            ErrorCode::ChainIncomplete,
            format!("PathLenConstraint exceeded: max={allowed}, below={intermediates_below}"),
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::algorithms::DEFAULT;
    use crate::checks;
    use crate::testing::TestPki;
    use x509_cert::ext::pkix::KeyUsages;

    const NOW: Timestamp = TestPki::NOW;

    fn options(now: Timestamp) -> PathOptions<'static> {
        PathOptions {
            now,
            algorithms: DEFAULT,
            max_clock_skew: Duration::ZERO,
            ee_checks: &[],
            model: ValidityModel::Shell,
        }
    }

    fn codes(result: &ValidationResult) -> Vec<(ErrorCode, &str)> {
        result
            .errors
            .iter()
            .map(|e| (e.code, e.subject.as_str()))
            .collect()
    }

    #[test]
    fn path_006_brainpool_nist_and_mixed_chains_validate() {
        let pki = TestPki::new();
        for chain in [
            vec![
                pki.ee_arzt.clone(),
                pki.sub_ca_hba.clone(),
                pki.rca1.clone(),
            ],
            vec![
                pki.ee_zeta.clone(),
                pki.sub_ca_komp.clone(),
                pki.rca7.clone(),
            ],
            vec![
                pki.ee_mixed.clone(),
                pki.sub_ca_mixed.clone(),
                pki.rca1.clone(),
            ],
        ] {
            let result = validate_path(&chain, &options(NOW)).unwrap();
            assert!(result.valid, "{:?}", result.errors);
            assert_eq!(
                result.positions,
                [
                    ChainPosition::EndEntity,
                    ChainPosition::SubCa,
                    ChainPosition::Root
                ]
            );
            assert_eq!(result.cert_results[0].subject, chain[0].subject_cn());
        }
    }

    #[test]
    fn path_002_expired_and_not_yet_valid_end_entities() {
        let pki = TestPki::new();
        let tail = [pki.sub_ca_hba.clone(), pki.rca1.clone()];
        for (ee, code) in [
            (&pki.ee_expired, ErrorCode::Expired),
            (&pki.ee_not_yet_valid, ErrorCode::NotYetValid),
        ] {
            let chain: Vec<_> = [ee.clone()]
                .into_iter()
                .chain(tail.iter().cloned())
                .collect();
            let result = validate_path(&chain, &options(NOW)).unwrap();
            assert!(!result.valid);
            assert_eq!(codes(&result), [(code, ee.subject_cn())]);
        }
    }

    #[test]
    fn clock_skew_widens_the_validity_window() {
        let pki = TestPki::new();
        // ee-not-yet-valid starts a day after NOW.
        let chain = [
            pki.ee_not_yet_valid.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ];
        let within = |skew| {
            let options = PathOptions {
                max_clock_skew: Duration::from_secs(skew),
                ..options(NOW)
            };
            validate_path(&chain, &options).unwrap().valid
        };
        assert!(within(86_400));
        assert!(!within(86_399));
    }

    #[test]
    fn path_004_critical_extensions_must_be_processed() {
        let pki = TestPki::new();
        let validate = |chain: &[Certificate]| validate_path(chain, &options(NOW)).unwrap();

        let unknown = validate(&[
            pki.ee_critical_unknown.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ]);
        assert_eq!(
            codes(&unknown),
            [(
                ErrorCode::UnrecognizedCriticalExtension,
                "EE-Critical-Unknown TEST-ONLY"
            )]
        );
        assert_eq!(
            unknown.errors[0].message,
            "critical extension 1.3.6.1.4.1.99999.1 is not processed (RFC 5280 §4.2)"
        );

        let eku = validate(&[
            pki.ee_critical_eku.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ]);
        assert!(eku.valid, "{:?}", eku.errors);

        let constrained = validate(&[
            pki.ee_under_name_constraints.clone(),
            pki.sub_ca_name_constraints.clone(),
            pki.rca1.clone(),
        ]);
        assert_eq!(
            codes(&constrained),
            [(
                ErrorCode::UnrecognizedCriticalExtension,
                "GEM.SubCA-NameConstraints TEST-ONLY"
            )]
        );
    }

    fn short_chain(ee: &Certificate, pki: &TestPki) -> [Certificate; 3] {
        [ee.clone(), pki.sub_ca_short.clone(), pki.rca1.clone()]
    }

    fn warning_codes(result: &ValidationResult) -> Vec<(ErrorCode, &str)> {
        result
            .warnings
            .iter()
            .map(|w| (w.code, w.subject.as_str()))
            .collect()
    }

    /// gemKPT_PKI_TIP 2.4.2: under the Kompromissmodell a CA counts as it was when it
    /// issued the certificate below; expired since, it is a warning.
    #[test]
    fn path_002_kompromissmodell_accepts_a_ca_that_expired_after_issuing() {
        let pki = TestPki::new();
        let options = PathOptions {
            model: ValidityModel::Compromise,
            ..options(TestPki::AFTER_SHORT)
        };
        let result = validate_path(&short_chain(&pki.ee_short_hci_aut, &pki), &options).unwrap();
        assert!(result.valid, "{:?}", result.errors);
        assert_eq!(
            warning_codes(&result),
            [(ErrorCode::CaExpired, "GEM.SubCA-Short TEST-ONLY")]
        );
        assert!(
            result.warnings[0]
                .message
                .contains("is accepted under the Kompromissmodell for HBA and SMC-B"),
            "{}",
            result.warnings[0].message
        );
    }

    /// gemKPT_PKI_TIP 2.4.2: a certificate issued after its CA expired is not valid
    /// under the Kompromissmodell either.
    #[test]
    fn path_002_kompromissmodell_rejects_a_certificate_issued_after_the_ca_expired() {
        let pki = TestPki::new();
        let options = PathOptions {
            model: ValidityModel::Compromise,
            ..options(TestPki::AFTER_SHORT)
        };
        let result = validate_path(&short_chain(&pki.ee_after_short, &pki), &options).unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::Expired, "GEM.SubCA-Short TEST-ONLY")]
        );
        assert!(warning_codes(&result).is_empty(), "{:?}", result.warnings);
    }

    /// gemKPT_PKI_TIP 2.4.1: under the shell model every certificate must be valid at the
    /// reference time.
    #[test]
    fn path_002_shell_model_rejects_a_chain_whose_ca_has_expired() {
        let pki = TestPki::new();
        let result = validate_path(
            &short_chain(&pki.ee_short_fd_tls_s, &pki),
            &options(TestPki::AFTER_SHORT),
        )
        .unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::Expired, "GEM.SubCA-Short TEST-ONLY")]
        );
    }

    /// gemKPT_PKI_TIP 2.4: the Kompromissmodell for every nonQES certificate of HBA and
    /// SMC-B, the shell model for components and the eGK.
    #[test]
    fn path_003_the_certificate_type_picks_the_validity_model() {
        use crate::CertificateType as T;
        for t in [T::HpAut, T::HpEnc, T::HciAut, T::HciEnc, T::HciOsig] {
            assert_eq!(ValidityModel::for_type(t), ValidityModel::Compromise, "{t}");
        }
        for t in [T::ChAut, T::ChEnc, T::FdTlsS, T::FdSig, T::ZdTlsS, T::HpQes] {
            assert_eq!(ValidityModel::for_type(t), ValidityModel::Shell, "{t}");
        }
    }

    #[test]
    fn path_002_expired_sub_ca_is_flagged_not_the_end_entity() {
        let pki = TestPki::new();
        let chain = [
            pki.ee_under_expired.clone(),
            pki.sub_ca_expired.clone(),
            pki.rca1.clone(),
        ];
        let result = validate_path(&chain, &options(NOW)).unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::Expired, "GEM.SubCA-Expired TEST-ONLY")]
        );
    }

    #[test]
    fn path_002_validity_follows_the_given_instant() {
        let pki = TestPki::new();
        let chain = [
            pki.ee_expired.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ];
        // The SubCA only starts at NOW; before it, the expired end entity was valid.
        let earlier = Timestamp(pki.ee_expired.not_before().0 + 86_400);
        let result = validate_path(&chain, &options(earlier)).unwrap();
        assert!(result.has_error(ErrorCode::NotYetValid));
        assert!(!result.has_error(ErrorCode::Expired));
    }

    #[test]
    fn path_006_foreign_links_fail_the_signature_check() {
        let pki = TestPki::new();
        let rsa_root = crate::cert::tests::fixture(crate::cert::tests::RCA2_RSA);
        for chain in [
            [pki.ee_arzt.clone(), rsa_root, pki.rca1.clone()],
            [
                pki.ee_arzt.clone(),
                pki.sub_ca_komp.clone(),
                pki.rca7.clone(),
            ],
        ] {
            let result = validate_path(&chain, &options(NOW)).unwrap();
            assert!(
                result.has_error(ErrorCode::SignatureInvalid),
                "{:?}",
                result.errors
            );
        }
    }

    #[test]
    fn path_005_path_length_constraint() {
        let pki = TestPki::new();
        let chain = [
            pki.ee_deep.clone(),
            pki.sub_sub_ca.clone(),
            pki.sub_ca_pathlen0.clone(),
            pki.rca1.clone(),
        ];
        let result = validate_path(&chain, &options(NOW)).unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::ChainIncomplete, "GEM.SubCA-PathLen0 TEST-ONLY")]
        );
        assert!(result.errors[0].message.contains("max=0, below=1"));
    }

    #[test]
    fn path_005_end_entity_as_issuer_is_not_a_ca() {
        let pki = TestPki::new();
        let chain = [
            pki.ee_under_ee.clone(),
            pki.ee_arzt.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ];
        let result = validate_path(&chain, &options(NOW)).unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::ChainIncomplete, "Dr. Arzt TEST-ONLY")]
        );
    }

    #[test]
    fn end_entity_checks_run_on_the_end_entity_only() {
        let pki = TestPki::new();
        let chain = [
            pki.ee_arzt.clone(),
            pki.sub_ca_hba.clone(),
            pki.rca1.clone(),
        ];
        let ee_checks = [checks::key_usage(&[KeyUsages::KeyAgreement])];
        let result = validate_path(
            &chain,
            &PathOptions {
                ee_checks: &ee_checks,
                ..options(NOW)
            },
        )
        .unwrap();
        assert_eq!(
            codes(&result),
            [(ErrorCode::KeyUsageMismatch, "Dr. Arzt TEST-ONLY")]
        );
    }

    #[test]
    fn path_005_a_chain_needs_two_certificates() {
        let pki = TestPki::new();
        assert!(matches!(
            validate_path(&[pki.ee_arzt], &options(NOW)),
            Err(Error::Malformed { .. })
        ));
    }
}
