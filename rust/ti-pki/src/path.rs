//! Path validation of a built chain per RFC 5280 §6, plus the end-entity
//! checks a profile requires. Every certificate must be within its validity
//! window; every CA must be marked as such, allow certificate signing and
//! respect its path-length constraint; each link's signature is verified
//! under its issuer's key, for ECDSA on Brainpool and NIST curves and for RSA.

use core::time::Duration;

use crate::algorithms::AlgorithmSet;
use crate::checks::CertificateCheck;
use crate::error::{ErrorCode, ValidationError};
use crate::time::Timestamp;
use crate::validate::{CertResult, ChainPosition, ValidationResult};
use crate::{Certificate, Error};

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
}

/// Validates `chain` (end entity first, root last, as [`build_chain`] returns it)
/// against RFC 5280 §6 and the end-entity checks.
///
/// Every certificate must be valid at `now`. Every CA below the end entity must be
/// marked as a CA, must allow certificate signing if it restricts key usage, and must
/// not have more intermediates beneath it than its path length constraint allows. Every
/// link's signature must verify under the next certificate's key. All findings are
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
        if let Err(e) = check_validity(cert, options.now, options.max_clock_skew) {
            result.add_error(e);
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
    fn brainpool_nist_and_mixed_chains_validate() {
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
    fn expired_and_not_yet_valid_end_entities() {
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
    fn expired_sub_ca_is_flagged_not_the_end_entity() {
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
    fn validity_follows_the_given_instant() {
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
    fn foreign_links_fail_the_signature_check() {
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
    fn path_length_constraint() {
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
    fn end_entity_as_issuer_is_not_a_ca() {
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
    fn a_chain_needs_two_certificates() {
        let pki = TestPki::new();
        assert!(matches!(
            validate_path(&[pki.ee_arzt], &options(NOW)),
            Err(Error::Malformed { .. })
        ));
    }
}
