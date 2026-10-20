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

//! The validator and its result. [`Validator::validate`] runs chain building, path
//! validation, the gemSpec_Krypt key admissibility check and the revocation check,
//! and folds every finding into one result: whether the certificate is valid, the
//! errors with an [`ErrorCode`] each, the warnings, and the built chain with each
//! certificate's position and revocation outcome.

use core::fmt;
use core::time::Duration;
use std::borrow::Cow;
use std::sync::Arc;

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

use crate::algorithms::AlgorithmSet;
use crate::cert_type::CertificateType;
use crate::checks::{self, CertificateCheck};
use crate::error::{ErrorCode, ValidationError, ValidationWarning};
use crate::key::{KeyStatus, classify_key};
use crate::path::{PathOptions, validate_path};
use crate::revocation::{
    ResponderAuthorization, RevocationChecker, RevocationFinding, RevocationMode, RevocationResult,
    apply_revocation,
};
use crate::time::Timestamp;
use crate::{Certificate, Error, TrustConfig, TrustStore, build_chain};

/// A certificate's role in a validated chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChainPosition {
    /// The end entity, the certificate the caller asked about.
    EndEntity,
    /// An intermediate CA between the end entity and the root.
    SubCa,
    /// The trusted root.
    Root,
}

impl ChainPosition {
    /// The stable string form, as in `gempki`: `end_entity`, `sub_ca`, `root`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChainPosition::EndEntity => "end_entity",
            ChainPosition::SubCa => "sub_ca",
            ChainPosition::Root => "root",
        }
    }
}

impl fmt::Display for ChainPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What validation recorded about one certificate of the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertResult {
    /// The certificate's common name.
    pub subject: String,
    /// Its role in the chain.
    pub position: ChainPosition,
    /// What its revocation source answered; `None` when revocation was not checked
    /// for this certificate or the source could not be consulted.
    pub revocation: Option<RevocationResult>,
}

/// The outcome of one validation.
///
/// `valid` is true only when every check passed; `errors` lists what made it false.
/// `warnings` are observations that did not affect the verdict. `chain`, `positions` and
/// `cert_results` are parallel: `chain[i]` sits at `positions[i]` and is detailed in
/// `cert_results[i]`.
#[derive(Clone, Debug, Default)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub valid: bool,
    /// The chain as built, end entity first.
    pub chain: Vec<Certificate>,
    /// The role of each chain element.
    pub positions: Vec<ChainPosition>,
    /// Why the certificate is not valid.
    pub errors: Vec<ValidationError>,
    /// Non-fatal observations.
    pub warnings: Vec<ValidationWarning>,
    /// Per-certificate detail.
    pub cert_results: Vec<CertResult>,
}

impl ValidationResult {
    /// Whether any error carries `code`, e.g. to tell revoked from expired.
    pub fn has_error(&self, code: ErrorCode) -> bool {
        self.errors.iter().any(|e| e.code == code)
    }

    /// Records `error` and marks the result invalid.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
        self.valid = false;
    }

    /// Whether any warning carries `code`.
    pub fn has_warning(&self, code: ErrorCode) -> bool {
        self.warnings.iter().any(|w| w.code == code)
    }
}

/// Validates end-entity certificates against a [`TrustStore`]: chain building through
/// the supplied and the store's intermediates, RFC 5280 path validation with the
/// end-entity requirements below, the gemSpec_Krypt key check and revocation.
///
/// Revocation is checked for the end entity at its CA and, unless
/// `skip_sub_ca_revocation`, for every CA at its issuer: a CA's standing comes from OCSP
/// rather than from its TSL listing. The root has no issuer to ask.
///
/// Built from a [`TrustConfig`] with [`Validator::new`] and adjusted by struct update;
/// a [`Profile`](crate::profile::Profile) fills in the end-entity requirements.
#[derive(Clone, Debug)]
pub struct Validator {
    /// The roots a chain must end in, and the TSL's intermediates.
    pub store: Arc<TrustStore>,
    /// The algorithms signatures may be verified with.
    pub algorithms: Cow<'static, AlgorithmSet>,
    /// How a non-Good revocation outcome affects the verdict.
    pub revocation: RevocationMode,
    /// Check revocation for the end entity only, not for its CAs.
    pub skip_sub_ca_revocation: bool,
    /// Report certificates outside their validity window as warnings, not errors.
    pub allow_expired: bool,
    /// Clock skew tolerated at the edges of validity windows.
    pub max_clock_skew: Duration,
    /// Key usage bits the end entity must all have.
    pub required_key_usage: Vec<KeyUsages>,
    /// Extended key usages of which the end entity must have one; empty for none.
    pub allowed_ext_key_usages: Vec<ObjectIdentifier>,
    /// Certificate policies the end entity must all assert.
    pub required_policies: Vec<ObjectIdentifier>,
    /// Admission roles of which the end entity must assert one; empty for none.
    pub required_role_oids: Vec<ObjectIdentifier>,
    /// The host the end entity must name if its commonName names one (A_30046 (5) of
    /// C_12791), e.g. the server a TLS connection went to.
    pub expected_fqdn: Option<String>,
    /// The certificate type the end entity is validated as; its OID must be among the
    /// types the verified TSL lets the issuing CA issue (TUC_PKI_007). Without it, the
    /// type detected from the certificate is checked.
    pub cert_type: Option<CertificateType>,
}

impl Validator {
    /// A validator with `config`'s algorithms, revocation mode, expiry relaxation and
    /// clock skew, checking every CA's revocation and requiring nothing of the end
    /// entity beyond RFC 5280.
    pub fn new(config: &TrustConfig, store: Arc<TrustStore>) -> Self {
        Validator {
            store,
            algorithms: config.algorithms.clone(),
            revocation: config.revocation,
            skip_sub_ca_revocation: false,
            allow_expired: config.allow_expired,
            max_clock_skew: config.max_clock_skew,
            required_key_usage: Vec::new(),
            allowed_ext_key_usages: Vec::new(),
            required_policies: Vec::new(),
            required_role_oids: Vec::new(),
            expected_fqdn: None,
            cert_type: None,
        }
    }

    /// Requires the end entity's commonName, if it names a host, to name `fqdn`.
    #[must_use]
    pub fn with_expected_fqdn(mut self, fqdn: impl Into<String>) -> Self {
        self.expected_fqdn = Some(fqdn.into());
        self
    }

    /// Requires of the end entity what gemSpec_PKI requires of every certificate of
    /// type `t` ([`CertificateType::spec`]).
    #[must_use]
    pub fn with_type_baseline(mut self, t: CertificateType) -> Self {
        self.cert_type = Some(t);
        let spec = t.spec();
        self.required_key_usage = spec.key_usage.to_vec();
        self.allowed_ext_key_usages = spec.ext_key_usage.to_vec();
        self.required_policies = spec.policies.to_vec();
        self.required_role_oids = spec.role_oids.to_vec();
        self
    }

    /// The end-entity requirements as the checks path validation runs. The admission
    /// roles are not among them: [`validate`](Self::validate) checks them only once
    /// everything else succeeded.
    pub fn ee_checks(&self) -> Vec<CertificateCheck> {
        let mut ee_checks = Vec::new();
        if !self.required_policies.is_empty() {
            ee_checks.push(checks::certificate_policies(&self.required_policies));
        }
        if !self.required_key_usage.is_empty() {
            ee_checks.push(checks::key_usage(&self.required_key_usage));
        }
        if !self.allowed_ext_key_usages.is_empty() {
            ee_checks.push(checks::any_ext_key_usage(&self.allowed_ext_key_usages));
        }
        if let Some(fqdn) = &self.expected_fqdn {
            ee_checks.push(checks::fqdn(fqdn));
        }
        ee_checks
    }

    /// Validates `certs[0]` as the end entity at `now`, with `certs[1..]` as candidate
    /// intermediates (from a TLS handshake or an `x5c` header) besides the store's.
    /// `checker` answers the revocation questions; pass
    /// [`Unchecked`](crate::revocation::Unchecked) with
    /// [`RevocationMode::Disabled`] to validate offline.
    ///
    /// Every policy-level failure lands in the result's errors. The required admission
    /// roles are checked last, and only for a certificate that is valid otherwise
    /// (A_30046 (4) of C_12791).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] only for an empty `certs`.
    pub async fn validate(
        &self,
        certs: &[Certificate],
        now: Timestamp,
        checker: &impl RevocationChecker,
    ) -> Result<ValidationResult, Error> {
        let Some((leaf, supplied)) = certs.split_first() else {
            return Err(Error::Malformed {
                what: "chain",
                reason: "no certificate to validate".into(),
            });
        };
        let candidates: Vec<Certificate> = supplied
            .iter()
            .chain(self.store.intermediates())
            .cloned()
            .collect();
        let chain = match build_chain(leaf, &candidates, &self.store) {
            Ok(chain) => chain,
            Err(e) => return Ok(incomplete(e.partial, e.error)),
        };
        let ee_checks = self.ee_checks();
        let mut result = validate_path(
            &chain,
            &PathOptions {
                now,
                algorithms: &self.algorithms,
                max_clock_skew: self.max_clock_skew,
                ee_checks: &ee_checks,
            },
        )?;
        if self.allow_expired {
            downgrade_validity_errors(&mut result);
        }
        check_key(&chain[0], now, &mut result);
        self.check_tsl_type(&chain, &mut result);
        self.check_ca_revoked_in_tsl(&chain, &mut result);
        self.check_revocation(&chain, now, checker, &mut result)
            .await;
        if result.valid
            && !self.required_role_oids.is_empty()
            && let Err(mut error) = checks::role_oid(&self.required_role_oids)(&chain[0])
        {
            if error.subject.is_empty() {
                chain[0].subject_cn().clone_into(&mut error.subject);
            }
            result.add_error(error);
        }
        Ok(result)
    }

    /// [`validate`](Self::validate) over PEM certificates, the first block the end
    /// entity.
    ///
    /// # Errors
    ///
    /// [`Error::Pem`] or [`Error::Der`] for input that does not parse,
    /// [`Error::Malformed`] if it holds no certificate.
    pub async fn validate_pem(
        &self,
        pem: &[u8],
        now: Timestamp,
        checker: &impl RevocationChecker,
    ) -> Result<ValidationResult, Error> {
        let certs = crate::parse_pem_certificates(pem)?;
        self.validate(&certs, now, checker).await
    }

    async fn check_revocation(
        &self,
        chain: &[Certificate],
        now: Timestamp,
        checker: &impl RevocationChecker,
        result: &mut ValidationResult,
    ) {
        if self.revocation == RevocationMode::Disabled {
            return;
        }
        let links = if self.skip_sub_ca_revocation {
            1
        } else {
            chain.len() - 1
        };
        for (i, link) in chain.windows(2).take(links).enumerate() {
            let (cert, issuer) = (&link[0], &link[1]);
            let outcome = checker.check(cert, issuer, &self.store).await;
            if let Ok(revocation) = &outcome {
                if let Some(warning) = not_rfc6960(revocation, cert, issuer) {
                    result.warnings.push(warning);
                }
                result.cert_results[i].revocation = Some(revocation.clone());
            }
            match apply_revocation(self.revocation, cert.subject_cn(), &outcome, now) {
                Some(RevocationFinding::Error(e)) => result.add_error(e),
                Some(RevocationFinding::Warning(w)) => result.warnings.push(w),
                None => {}
            }
        }
    }
}

impl Validator {
    /// TUC_PKI_007 steps 7 – 9 against the verified TSL in the store: the end entity's
    /// type OID must be among those its issuing CA's TSL entry lists. Without a verified
    /// TSL nothing is checked; with one that states no types for the issuer, a warning
    /// says the type went unchecked (variant 7a). The TSL signer is checked by
    /// TUC_PKI_011 instead.
    /// A CA the TSL lists as revoked still vouches for the end entities it issued
    /// before its `StatusStartingTime` (gemSpec_PKI Tab_PKI_271, TUC_PKI_002 step 5:
    /// the end entity's `notBefore` against the time), not for later ones.
    fn check_ca_revoked_in_tsl(&self, chain: &[Certificate], result: &mut ValidationResult) {
        let (Some(leaf), Some(issuer)) = (chain.first(), chain.get(1)) else {
            return;
        };
        let Some(revoked) = self.store.revoked_since(issuer) else {
            return;
        };
        if leaf.not_before() < revoked {
            result.warnings.push(
                ValidationWarning::new(
                    ErrorCode::IssuedBeforeCaRevocation,
                    format!(
                        "the TSL lists {:?} as revoked since {revoked}; issued before, so treated as usual",
                        issuer.subject_cn()
                    ),
                )
                .with_subject(leaf.subject_cn()),
            );
        } else {
            result.add_error(
                ValidationError::new(
                    ErrorCode::CaRevokedInTsl,
                    format!(
                        "the TSL lists {:?} as revoked since {revoked}, and the certificate was issued at or after that",
                        issuer.subject_cn()
                    ),
                )
                .with_subject(leaf.subject_cn()),
            );
        }
    }

    fn check_tsl_type(&self, chain: &[Certificate], result: &mut ValidationResult) {
        let (Some(leaf), Some(issuer)) = (chain.first(), chain.get(1)) else {
            return;
        };
        if !self.store.has_tsl_types() {
            return;
        }
        let Some(cert_type) = self
            .cert_type
            .or_else(|| crate::cert_type::detect_certificate_type(leaf))
        else {
            return;
        };
        if cert_type == CertificateType::TslSig {
            return;
        }
        match self.store.tsl_types_of(issuer) {
            Some(types) if types.contains(&cert_type.oid()) => {}
            Some(_) => result.add_error(
                ValidationError::new(
                    ErrorCode::CertTypeCaNotAuthorized,
                    format!(
                        "the TSL does not list {cert_type} among the types {:?} may issue",
                        issuer.subject_cn()
                    ),
                )
                .with_subject(leaf.subject_cn()),
            ),
            None => result.warnings.push(ValidationWarning::new(
                ErrorCode::CertTypeUnchecked,
                format!(
                    "{cert_type} not checked against the TSL: it states no certificate types \
                     for {:?}",
                    issuer.subject_cn()
                ),
            )),
        }
    }
}

/// The warning for a response whose signer only the same-TSP rule authorized, so the
/// deviation from RFC 6960 is visible in every result that relied on it.
fn not_rfc6960(
    revocation: &RevocationResult,
    cert: &Certificate,
    issuer: &Certificate,
) -> Option<ValidationWarning> {
    let Some(ResponderAuthorization::SameTspDelegate { ca, tsp }) = &revocation.authorization
    else {
        return None;
    };
    Some(
        ValidationWarning::new(
            ErrorCode::OcspResponderNotRfc6960,
            format!(
                "OCSP responder {:?} is not RFC 6960 conform: certified by {ca:?}, not by the \
                 issuing CA {:?}; accepted as a delegate of the same TSP {tsp:?}",
                revocation.responder_name,
                issuer.subject_cn()
            ),
        )
        .with_subject(cert.subject_cn()),
    )
}

/// The result for a chain that reached no root: what the walk found, nothing
/// positioned as a root.
fn incomplete(partial: Vec<Certificate>, error: ValidationError) -> ValidationResult {
    let positions: Vec<ChainPosition> = (0..partial.len())
        .map(|i| {
            if i == 0 {
                ChainPosition::EndEntity
            } else {
                ChainPosition::SubCa
            }
        })
        .collect();
    ValidationResult {
        valid: false,
        cert_results: partial
            .iter()
            .zip(&positions)
            .map(|(cert, position)| CertResult {
                subject: cert.subject_cn().to_owned(),
                position: *position,
                revocation: None,
            })
            .collect(),
        chain: partial,
        positions,
        errors: vec![error],
        warnings: Vec::new(),
    }
}

fn downgrade_validity_errors(result: &mut ValidationResult) {
    let (validity, rest): (Vec<_>, Vec<_>) = result
        .errors
        .drain(..)
        .partition(|e| matches!(e.code, ErrorCode::Expired | ErrorCode::NotYetValid));
    result.errors = rest;
    result.warnings.extend(validity.into_iter().map(|e| {
        ValidationWarning::new(
            e.code,
            format!("{} (expired certificates allowed)", e.message),
        )
        .with_subject(e.subject)
    }));
    result.valid = result.errors.is_empty();
}

/// Holds the end-entity key to gemSpec_Krypt. Only the end entity: which CAs may sign
/// is the trust store's business, and historical RSA roots must keep validating the
/// chains issued under them.
fn check_key(ee: &Certificate, now: Timestamp, result: &mut ValidationResult) {
    let (status, key) = classify_key(ee.public_key_info(), now);
    match status {
        KeyStatus::NotAdmissible => result.add_error(
            ValidationError::new(
                ErrorCode::KeyNotAdmissible,
                format!("public key {key} is not admissible for a TI certificate (gemSpec_Krypt)"),
            )
            .with_subject(ee.subject_cn()),
        ),
        KeyStatus::PhasedOut => result.warnings.push(
            ValidationWarning::new(
                ErrorCode::KeyPhasedOut,
                format!("public key {key} is past its gemSpec_Krypt admissibility date"),
            )
            .with_subject(ee.subject_cn()),
        ),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_error_matches_by_code() {
        let result = ValidationResult {
            errors: vec![ValidationError::new(ErrorCode::Expired, "expired")],
            warnings: vec![ValidationWarning::new(ErrorCode::KeyPhasedOut, "RSA 2048")],
            ..ValidationResult::default()
        };
        assert!(result.has_error(ErrorCode::Expired));
        assert!(!result.has_error(ErrorCode::Revoked));
        assert!(result.has_warning(ErrorCode::KeyPhasedOut));
        assert_eq!(ChainPosition::SubCa.to_string(), "sub_ca");
    }

    #[cfg(feature = "brainpool")]
    mod validator {
        use futures_lite::future::block_on;

        use super::*;
        use crate::revocation::Unchecked;
        use crate::testing::{TestPki, typed};

        fn validator(pki: &TestPki, revocation: RevocationMode) -> Validator {
            let config = TrustConfig {
                revocation,
                ..TrustConfig::for_anchor(pki.rca1.der().to_vec())
            };
            let store = TrustStore::new([pki.rca1.clone(), pki.rca7.clone()]);
            Validator::new(&config, Arc::new(store))
        }

        fn codes(result: &ValidationResult) -> Vec<(ErrorCode, &str)> {
            result
                .errors
                .iter()
                .map(|e| (e.code, e.subject.as_str()))
                .collect()
        }

        fn offline(validator: &Validator, certs: &[Certificate]) -> ValidationResult {
            block_on(validator.validate(certs, TestPki::NOW, &Unchecked)).unwrap()
        }

        /// Tab_PKI_271 and TUC_PKI_002 step 5: under a CA the TSL lists as revoked, an
        /// end entity issued before the CA's StatusStartingTime is treated as usual,
        /// one issued at or after it is not valid.
        #[test]
        fn a_revoked_tsl_ca_vouches_only_for_what_it_issued_before() {
            let pki = TestPki::new();
            let issued = pki.ee_mixed.not_before();
            let store = |revoked_since| {
                Arc::new(TrustStore::new([pki.rca1.clone()]).with_intermediates(vec![
                    crate::tsl::Intermediate {
                        certificate: pki.sub_ca_mixed.clone(),
                        provider: "Test TSP".into(),
                        revoked_since,
                    },
                ]))
            };
            let run = |revoked_since| {
                let v = Validator {
                    store: store(revoked_since),
                    ..validator(&pki, RevocationMode::Disabled)
                };
                offline(&v, std::slice::from_ref(&pki.ee_mixed))
            };

            let before = run(Some(Timestamp(issued.0 + 1)));
            assert!(before.valid, "{:?}", before.errors);
            assert!(before.has_warning(ErrorCode::IssuedBeforeCaRevocation));

            for since in [issued, Timestamp(issued.0 - 1)] {
                let after = run(Some(since));
                assert_eq!(
                    codes(&after),
                    [(ErrorCode::CaRevokedInTsl, pki.ee_mixed.subject_cn())],
                    "revoked since {since}"
                );
            }

            let in_accord = run(None);
            assert!(in_accord.valid, "{:?}", in_accord.errors);
            assert!(!in_accord.has_warning(ErrorCode::IssuedBeforeCaRevocation));
        }

        /// Answers every query with "revoked at" its time.
        struct RevokedAt(Timestamp);

        impl RevocationChecker for RevokedAt {
            async fn check(
                &self,
                _: &Certificate,
                _: &Certificate,
                _: &TrustStore,
            ) -> Result<RevocationResult, ValidationError> {
                Ok(RevocationResult {
                    status: crate::revocation::RevocationStatus::Revoked,
                    revoked_at: Some(self.0),
                    reason: "keyCompromise".into(),
                    ..RevocationResult::unknown(self.0, "")
                })
            }
        }

        /// TUC_PKI_006 8a and 8b through the validator: a chain validated for a time
        /// before the end entity's revocation is valid with a warning, one at or after it
        /// is revoked.
        #[test]
        fn tuc_pki_006_revocation_is_judged_at_the_reference_time() {
            let pki = TestPki::new();
            let chain = [pki.ee_arzt.clone(), pki.sub_ca_hba.clone()];
            let v = Validator {
                skip_sub_ca_revocation: true,
                ..validator(&pki, RevocationMode::HardFail)
            };
            let at = TestPki::NOW;
            let check =
                |revoked: Timestamp| block_on(v.validate(&chain, at, &RevokedAt(revoked))).unwrap();

            let later = check(Timestamp(at.0 + 1));
            assert!(later.valid, "{:?}", later.errors);
            assert!(later.has_warning(ErrorCode::RevokedAfterReferenceTime));

            for revoked in [at, Timestamp(at.0 - 1)] {
                assert_eq!(
                    codes(&check(revoked)),
                    [(ErrorCode::Revoked, "Dr. Arzt TEST-ONLY")],
                    "revoked at {revoked}"
                );
            }
        }

        #[test]
        fn offline_validation_with_the_stores_intermediates() {
            let pki = TestPki::new();
            let mut v = validator(&pki, RevocationMode::Disabled);
            let alone = offline(&v, std::slice::from_ref(&pki.ee_arzt));
            assert_eq!(
                codes(&alone),
                [(ErrorCode::ChainIncomplete, "Dr. Arzt TEST-ONLY")]
            );
            assert_eq!(alone.positions, [ChainPosition::EndEntity]);

            v.store = Arc::new(TrustStore::new([pki.rca1.clone()]).with_intermediates(vec![
                crate::tsl::Intermediate {
                    certificate: pki.sub_ca_hba.clone(),
                    provider: "Test TSP".into(),
                    revoked_since: None,
                },
            ]));
            let result = offline(&v, std::slice::from_ref(&pki.ee_arzt));
            assert!(result.valid, "{:?}", result.errors);
            assert_eq!(result.chain.len(), 3);
            assert!(result.cert_results.iter().all(|c| c.revocation.is_none()));
        }

        #[test]
        fn a_missing_checker_fails_closed() {
            let pki = TestPki::new();
            let chain = [pki.ee_arzt.clone(), pki.sub_ca_hba.clone()];
            let hard = offline(&validator(&pki, RevocationMode::HardFail), &chain);
            assert_eq!(
                codes(&hard),
                [
                    (ErrorCode::OcspUnavailable, "Dr. Arzt TEST-ONLY"),
                    (ErrorCode::OcspUnavailable, "GEM.SubCA-HBA TEST-ONLY"),
                ]
            );
            let soft = offline(&validator(&pki, RevocationMode::SoftFail), &chain);
            assert!(soft.valid);
            assert_eq!(soft.warnings.len(), 2);

            let ee_only = Validator {
                skip_sub_ca_revocation: true,
                ..validator(&pki, RevocationMode::HardFail)
            };
            assert_eq!(offline(&ee_only, &chain).errors.len(), 1);
        }

        /// A_30046 (5): a host named in the commonName must be the expected one.
        #[test]
        fn expected_fqdn() {
            let pki = TestPki::new();
            let chain = [pki.ee_zeta.clone(), pki.sub_ca_komp.clone()];
            let v = validator(&pki, RevocationMode::Disabled);
            let right = v.clone().with_expected_fqdn("zeta.ti-dienste.de");
            assert!(offline(&right, &chain).valid);
            let wrong = v.with_expected_fqdn("popp.ti-dienste.de");
            assert_eq!(
                codes(&offline(&wrong, &chain)),
                [(ErrorCode::FqdnMismatch, "zeta.ti-dienste.de TEST-ONLY")]
            );
        }

        #[test]
        fn expiry_key_and_baseline_findings() {
            let pki = TestPki::new();
            let v = validator(&pki, RevocationMode::Disabled);
            let expired = [pki.ee_expired.clone(), pki.sub_ca_hba.clone()];
            assert_eq!(
                codes(&offline(&v, &expired)),
                [(ErrorCode::Expired, "EE-Expired TEST-ONLY")]
            );
            let allowed = Validator {
                allow_expired: true,
                ..v.clone()
            };
            let result = offline(&allowed, &expired);
            assert!(result.valid);
            assert!(result.has_warning(ErrorCode::Expired));

            assert_eq!(
                codes(&offline(&v, std::slice::from_ref(&pki.ee_p521))),
                [(ErrorCode::KeyNotAdmissible, "P-521 TEST-ONLY")]
            );

            let hci = v.clone().with_type_baseline(CertificateType::HciAut);
            let typed_ok = offline(&hci, &[typed("type-hci-aut"), pki.sub_ca_komp.clone()]);
            assert!(typed_ok.valid, "{:?}", typed_ok.errors);
            let wrong = offline(&hci, &[typed("type-hp-aut"), pki.sub_ca_komp.clone()]);
            assert!(wrong.has_error(ErrorCode::PolicyMismatch));
            assert!(
                !wrong.has_error(ErrorCode::RoleOidMissing),
                "roles are checked only for an otherwise valid certificate"
            );
            let other_role = offline(
                &hci,
                &[typed("role-hci-aut-kim-anbieter"), pki.sub_ca_komp.clone()],
            );
            assert!(other_role.valid, "{:?}", other_role.errors);
            let roleless = Validator {
                required_role_oids: vec![crate::oid::PROF_VERSICHERTER],
                ..hci.clone()
            };
            let missing = offline(&roleless, &[typed("type-hci-aut"), pki.sub_ca_komp.clone()]);
            assert_eq!(
                codes(&missing),
                [(ErrorCode::RoleOidMissing, "type-hci-aut TEST-ONLY")]
            );
        }

        /// TUC_PKI_007: the verified TSL must list the end entity's type for its CA.
        #[test]
        fn tsl_states_the_types_a_ca_may_issue() {
            let pki = TestPki::new();
            let chain = [typed("type-hci-aut"), pki.sub_ca_komp.clone()];
            let with_types = |types: Vec<ObjectIdentifier>| Validator {
                store: Arc::new(
                    TrustStore::new([pki.rca1.clone(), pki.rca7.clone()])
                        .with_ca_types(vec![(pki.sub_ca_komp.clone(), types)]),
                ),
                ..validator(&pki, RevocationMode::Disabled)
                    .with_type_baseline(CertificateType::HciAut)
            };

            let listed = offline(&with_types(vec![crate::oid::CERT_TYPE_SMC_B_AUT]), &chain);
            assert!(listed.valid, "{:?}", listed.errors);
            assert!(listed.warnings.is_empty(), "{:?}", listed.warnings);

            let other = offline(&with_types(vec![crate::oid::CERT_TYPE_FD_SIG]), &chain);
            assert_eq!(
                codes(&other),
                [(ErrorCode::CertTypeCaNotAuthorized, "type-hci-aut TEST-ONLY")]
            );

            // The placeholder only: the TSL states nothing, so the type goes unchecked.
            let unstated = offline(&with_types(Vec::new()), &chain);
            assert!(unstated.valid);
            assert!(unstated.has_warning(ErrorCode::CertTypeUnchecked));

            // Without a verified TSL there is nothing to check against.
            let hci = validator(&pki, RevocationMode::Disabled)
                .with_type_baseline(CertificateType::HciAut);
            let none = offline(&hci, &chain);
            assert!(
                none.valid && none.warnings.is_empty(),
                "{:?}",
                none.warnings
            );

            // Without a profile, the detected type is the one checked.
            let detected = Validator {
                store: with_types(vec![crate::oid::CERT_TYPE_FD_SIG]).store,
                ..validator(&pki, RevocationMode::Disabled)
            };
            assert!(offline(&detected, &chain).has_error(ErrorCode::CertTypeCaNotAuthorized));
        }

        #[test]
        fn empty_input_and_pem() {
            let pki = TestPki::new();
            let v = validator(&pki, RevocationMode::Disabled);
            assert!(matches!(
                block_on(v.validate(&[], TestPki::NOW, &Unchecked)),
                Err(Error::Malformed { .. })
            ));
            let pem = include_str!("../tests/pki/ee-zeta.pem").to_owned()
                + include_str!("../tests/pki/sub-ca-komp.pem");
            let result =
                block_on(v.validate_pem(pem.as_bytes(), TestPki::NOW, &Unchecked)).unwrap();
            assert!(result.valid, "{:?}", result.errors);
        }

        #[cfg(feature = "load")]
        #[test]
        fn ocsp_for_the_end_entity_and_its_ca() {
            use crate::load::MockTransport;
            use crate::ocsp::OcspChecker;
            use crate::revocation::RevocationStatus;
            use crate::time::FixedClock;

            let pki = TestPki::new();
            let config = TrustConfig::for_anchor(pki.rca1.der().to_vec());
            let good = include_bytes!("../tests/pki/ocsp/good.der").to_vec();
            let revoked = include_bytes!("../tests/pki/ocsp/revoked.der").to_vec();
            let ca_good = include_bytes!("../tests/pki/ocsp/issuer-signed.der").to_vec();
            let check = |ee: &Certificate, script: Vec<Vec<u8>>| {
                let transport = MockTransport::posting(script.into_iter().map(Ok));
                let checker = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW))
                    .with_responder_url("http://ocsp.test/");
                let v = validator(&pki, RevocationMode::HardFail);
                let certs = [ee.clone(), pki.sub_ca_hba.clone()];
                let result = block_on(v.validate(&certs, TestPki::NOW, &checker)).unwrap();
                (result, transport.posts().len())
            };

            let (result, posts) = check(&pki.ee_arzt, vec![good, ca_good.clone()]);
            assert!(result.valid, "{:?}", result.errors);
            assert_eq!(posts, 2);
            let statuses: Vec<_> = result
                .cert_results
                .iter()
                .map(|c| c.revocation.as_ref().map(|r| r.status))
                .collect();
            assert_eq!(
                statuses,
                [
                    Some(RevocationStatus::Good),
                    Some(RevocationStatus::Good),
                    None
                ]
            );

            let (result, _) = check(&pki.ee_revoked, vec![revoked, ca_good.clone()]);
            assert_eq!(
                codes(&result),
                [(ErrorCode::Revoked, "EE-Revoked TEST-ONLY")]
            );

            // A delegate of another CA of the same TSP: accepted, with a warning.
            let foreign = include_bytes!("../tests/pki/ocsp/foreign-responder.der").to_vec();
            let transport = MockTransport::posting([Ok(foreign), Ok(ca_good)]);
            let checker = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW))
                .with_responder_url("http://ocsp.test/");
            let intermediate = |ca: &Certificate| crate::tsl::Intermediate {
                certificate: ca.clone(),
                provider: "TSP A".into(),
                revoked_since: None,
            };
            let v = Validator {
                store: Arc::new(
                    TrustStore::new([pki.rca1.clone(), pki.rca7.clone()]).with_intermediates(vec![
                        intermediate(&pki.sub_ca_hba),
                        intermediate(&pki.sub_ca_komp),
                    ]),
                ),
                ..validator(&pki, RevocationMode::HardFail)
            };
            let result =
                block_on(v.validate(std::slice::from_ref(&pki.ee_arzt), TestPki::NOW, &checker))
                    .unwrap();
            assert!(result.valid, "{:?}", result.errors);
            let warnings: Vec<String> = result.warnings.iter().map(ToString::to_string).collect();
            assert_eq!(
                warnings,
                [
                    "ti-pki[ocsp_responder_not_rfc6960] warning: OCSP responder \
                     \"SubCA-Komp OCSP-Signer TEST-ONLY\" is not RFC 6960 conform: certified by \
                     \"GEM.SubCA-Komp TEST-ONLY\", not by the issuing CA \"GEM.SubCA-HBA \
                     TEST-ONLY\"; accepted as a delegate of the same TSP \"TSP A\": \
                     \"Dr. Arzt TEST-ONLY\""
                ]
            );
        }
    }
}
