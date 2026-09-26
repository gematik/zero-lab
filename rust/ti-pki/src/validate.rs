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
    RevocationChecker, RevocationFinding, RevocationMode, RevocationResult, apply_revocation,
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
/// `skip_sub_ca_revocation`, for every CA at its issuer: the TSL is not authenticated,
/// so a CA's standing comes from OCSP rather than from its listing. The root has no
/// issuer to ask.
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
        }
    }

    /// Requires of the end entity what gemSpec_PKI requires of every certificate of
    /// type `t` ([`CertificateType::spec`]).
    #[must_use]
    pub fn with_type_baseline(mut self, t: CertificateType) -> Self {
        let spec = t.spec();
        self.required_key_usage = spec.key_usage.to_vec();
        self.allowed_ext_key_usages = spec.ext_key_usage.to_vec();
        self.required_policies = spec.policies.to_vec();
        self.required_role_oids = spec.role_oids.to_vec();
        self
    }

    /// The end-entity requirements as the checks path validation runs.
    pub fn ee_checks(&self) -> Vec<CertificateCheck> {
        let mut ee_checks = Vec::new();
        if !self.required_policies.is_empty() {
            ee_checks.push(checks::certificate_policies(&self.required_policies));
        }
        if !self.required_role_oids.is_empty() {
            ee_checks.push(checks::role_oid(&self.required_role_oids));
        }
        if !self.required_key_usage.is_empty() {
            ee_checks.push(checks::key_usage(&self.required_key_usage));
        }
        if !self.allowed_ext_key_usages.is_empty() {
            ee_checks.push(checks::any_ext_key_usage(&self.allowed_ext_key_usages));
        }
        ee_checks
    }

    /// Validates `certs[0]` as the end entity at `now`, with `certs[1..]` as candidate
    /// intermediates (from a TLS handshake or an `x5c` header) besides the store's.
    /// `checker` answers the revocation questions; pass
    /// [`Unchecked`](crate::revocation::Unchecked) with
    /// [`RevocationMode::Disabled`] to validate offline.
    ///
    /// Every policy-level failure lands in the result's errors.
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
        self.check_revocation(&chain, checker, &mut result).await;
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
            let outcome = checker.check(cert, issuer).await;
            if let Ok(revocation) = &outcome {
                result.cert_results[i].revocation = Some(revocation.clone());
            }
            match apply_revocation(self.revocation, cert.subject_cn(), &outcome) {
                Some(RevocationFinding::Error(e)) => result.add_error(e),
                Some(RevocationFinding::Warning(w)) => result.warnings.push(w),
                None => {}
            }
        }
    }
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
        use crate::revocation::{RevocationStatus, Unchecked};
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

            v.store = Arc::new(
                TrustStore::new([pki.rca1.clone()])
                    .with_intermediates(vec![pki.sub_ca_hba.clone()]),
            );
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
            assert!(wrong.has_error(ErrorCode::RoleOidMissing));
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

            let (result, _) = check(&pki.ee_revoked, vec![revoked, ca_good]);
            assert_eq!(
                codes(&result),
                [(ErrorCode::Revoked, "EE-Revoked TEST-ONLY")]
            );
        }
    }
}
