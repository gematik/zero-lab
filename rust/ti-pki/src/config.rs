//! Environment as data: everything that differs between TI environments is a named
//! field of [`TrustConfig`], and the library reads those fields, never the
//! environment itself.
//!
//! # Design rules
//!
//! 1. Library code never reads [`crate::Env`]. Every environment-dependent value
//!    is a named field of [`TrustConfig`]; `Env` appears in [`TrustConfig::preset`]
//!    and nowhere else in the crate.
//! 2. Relaxations are named negatively and default to strict: `revocation` is
//!    [`HardFail`](RevocationMode::HardFail), `accept_test_only_policies` and
//!    `allow_expired` are `false`. A forgotten field fails closed.
//! 3. [`TrustConfig`] is plainly constructible, so tests can build it from scratch.
//!    Adding a field is therefore a breaking change for this crate; the
//!    forward-compatible construction is struct update on
//!    [`TrustConfig::for_anchor`]. `Env` stays `#[non_exhaustive]`, the config does
//!    not.
//! 4. There is no `Default`. A default anchor is a security decision nobody made.
//! 5. One choke point: [`TrustConfig::validate`] checks that the pieces agree with
//!    each other and with the [`Tier`]; everything downstream assumes a consistent
//!    configuration.
//!
//! Signature algorithms are part of the configuration too ([`TrustConfig::algorithms`],
//! see [`crate::algorithms`]): the presets use the default set, which covers
//! the TI's brainpool anchors only with the `brainpool` feature, and `validate` refuses
//! an anchor no configured algorithm can check.
//!
//! Operators adjust fields on a preset rather than inventing environments: a
//! private mirror of the TSL is `TrustConfig { tsl_url: ..., ..TrustConfig::preset_prod() }`.
//!
//! Non-production presets carry TEST-ONLY anchors and exist only with the
//! `dangerous-nonprod` feature, so a production binary built without it cannot be
//! configured into trusting test material.

use std::borrow::Cow;
use std::time::Duration;

use der::{Decode, Encode};
use x509_cert::Certificate;

#[cfg(feature = "dangerous-nonprod")]
use crate::Env;
use crate::algorithms::{self, AlgorithmSet};
use crate::{Error, RevocationMode, Tier, anchors, roots, tsl};

/// Clock skew tolerated between us and a responder or issuer. The value the Go
/// implementation and the gematik reference implementation apply.
pub const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_millis(37_500);

/// Marker gematik puts in the subject of every non-production root.
const TEST_ONLY_MARKER: &str = "TEST-ONLY";

/// Everything environment-dependent that validation needs.
///
/// Build it from a preset or from [`TrustConfig::for_anchor`], adjust fields with
/// struct update, and check it with [`TrustConfig::validate`] before use:
///
/// ```
/// use ti_pki::{RevocationMode, Tier, TrustConfig};
///
/// let der = ti_pki::anchors::GEM_RCA8;
/// let config = TrustConfig {
///     revocation: RevocationMode::Disabled,
///     ..TrustConfig::for_anchor(der)
/// };
/// assert!(config.validate(Tier::Prod).is_err());
/// # #[cfg(feature = "brainpool")] // GEM.RCA8 is a brainpool key
/// assert!(config.validate(Tier::NonProd).is_ok());
/// ```
#[derive(Clone, Debug)]
pub struct TrustConfig {
    /// The single `GEM.RCA<n>` anchor everything chains to, as DER.
    pub anchor: Cow<'static, [u8]>,
    /// roots.json bytes, from a preset or fetched by the operator. Empty means the
    /// anchor is the only root.
    pub roots: Cow<'static, [u8]>,
    /// Where a fresh roots.json is downloaded from. Must be `https://`.
    pub roots_url: Cow<'static, str>,
    /// Where the TSL is downloaded from. Must be `https://`. The TSL is not
    /// authenticated; it only supplies candidate intermediates (see [`tsl`]).
    pub tsl_url: Cow<'static, str>,
    /// How a non-Good revocation outcome affects the verdict.
    pub revocation: RevocationMode,
    /// Accept the certificate policies gematik reserves for test cards.
    pub accept_test_only_policies: bool,
    /// Accept certificates outside their validity window.
    pub allow_expired: bool,
    /// Clock skew tolerated in validity and freshness checks.
    pub max_clock_skew: Duration,
    /// The signature algorithms every check may use; nothing outside this set verifies.
    pub algorithms: Cow<'static, AlgorithmSet>,
}

impl TrustConfig {
    /// Only the anchor is required; every policy field at its strictest value,
    /// `roots` empty, both URLs set to production and the
    /// [default algorithms](algorithms::DEFAULT). The intended base
    /// for struct update.
    pub fn for_anchor(anchor: impl Into<Cow<'static, [u8]>>) -> Self {
        TrustConfig {
            anchor: anchor.into(),
            roots: Cow::Borrowed(&[]),
            roots_url: Cow::Borrowed(roots::URL_PROD),
            tsl_url: Cow::Borrowed(tsl::URL_PROD),
            revocation: RevocationMode::HardFail,
            accept_test_only_policies: false,
            allow_expired: false,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            algorithms: Cow::Borrowed(algorithms::DEFAULT),
        }
    }

    /// Production preset: GEM.RCA8, the embedded production roots.json and the
    /// production TSL. Always available.
    pub fn preset_prod() -> Self {
        TrustConfig {
            roots: Cow::Borrowed(roots::ROOTS_PROD),
            ..Self::for_anchor(anchors::GEM_RCA8)
        }
    }

    /// Preset for any environment. Non-production presets use the TEST-ONLY anchor
    /// and roots of that environment and accept test-only policies; revocation stays
    /// strict, since the test environments run OCSP responders too.
    #[cfg(feature = "dangerous-nonprod")]
    pub fn preset(env: Env) -> Self {
        let nonprod =
            |anchor: &'static [u8], roots_url: &'static str, tsl_url: &'static str| TrustConfig {
                roots: Cow::Borrowed(roots::ROOTS_NONPROD),
                roots_url: Cow::Borrowed(roots_url),
                tsl_url: Cow::Borrowed(tsl_url),
                accept_test_only_policies: true,
                ..Self::for_anchor(anchor)
            };
        match env {
            Env::Prod => Self::preset_prod(),
            Env::Test => nonprod(anchors::GEM_RCA8_TEST_ONLY, roots::URL_TEST, tsl::URL_TEST),
            Env::Ref | Env::Dev => {
                nonprod(anchors::GEM_RCA7_TEST_ONLY, roots::URL_REF, tsl::URL_REF)
            }
            _ => {
                // Env::tier maps every variant other than Prod to NonProd, so an
                // environment added to ti-types later is non-production by
                // construction and gets the test preset until it has its own arm.
                debug_assert!(
                    env.tier() == Tier::NonProd,
                    "unknown {env} must be non-prod"
                );
                Self::preset(Env::Test)
            }
        }
    }

    /// Checks that the configuration is consistent in itself and fit for `tier`.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] if the anchor is not a DER certificate.
    /// [`Error::InconsistentConfig`] if either URL is not `https://`, if no configured
    /// algorithm handles the anchor's key type (a brainpool anchor without the
    /// `brainpool` feature, say), or, under
    /// [`Tier::Prod`], if the anchor is TEST-ONLY, revocation is not
    /// [`HardFail`](RevocationMode::HardFail), or either relaxation is on.
    pub fn validate(&self, tier: Tier) -> Result<(), Error> {
        let anchor = Certificate::from_der(&self.anchor)?;
        if !self.roots_url.starts_with("https://") {
            return Err(inconsistent("roots_url must be an https URL"));
        }
        if !self.tsl_url.starts_with("https://") {
            return Err(inconsistent("tsl_url must be an https URL"));
        }
        let key_alg = anchor
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .to_der()?;
        let key_alg = der::asn1::AnyRef::from_der(&key_alg)?;
        if !algorithms::supports_key(&self.algorithms, key_alg.value()) {
            return Err(inconsistent(
                "no configured signature algorithm handles the anchor's key type",
            ));
        }
        match tier {
            Tier::NonProd => Ok(()),
            Tier::Prod => {
                let subject = anchor.tbs_certificate().subject().to_string();
                if subject.contains(TEST_ONLY_MARKER) {
                    return Err(inconsistent("TEST-ONLY anchor in production"));
                }
                if self.revocation != RevocationMode::HardFail {
                    return Err(inconsistent("production requires HardFail revocation"));
                }
                if self.accept_test_only_policies {
                    return Err(inconsistent(
                        "production must not accept test-only policies",
                    ));
                }
                if self.allow_expired {
                    return Err(inconsistent(
                        "production must not allow expired certificates",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "test-util")]
impl TrustConfig {
    /// Lab CA configuration for tests in downstream crates: the given anchor,
    /// revocation off, test-only policies accepted. Validates only under
    /// [`Tier::NonProd`].
    pub fn for_lab_ca(anchor_der: &[u8]) -> Self {
        TrustConfig {
            revocation: RevocationMode::Disabled,
            accept_test_only_policies: true,
            ..Self::for_anchor(anchor_der.to_vec())
        }
    }
}

fn inconsistent(reason: &'static str) -> Error {
    Error::InconsistentConfig { reason }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A production-valid configuration that needs no optional algorithm: the GEM.RCA10
    /// root (P-256) as anchor. For tests about everything but the presets.
    pub(crate) fn nist_prod_config() -> TrustConfig {
        let (rca10, ..) = crate::algorithms::tests::prod_root("GEM.RCA10");
        TrustConfig::for_anchor(rca10.to_der().unwrap())
    }

    fn reason(result: Result<(), Error>) -> &'static str {
        match result {
            Err(Error::InconsistentConfig { reason }) => reason,
            other => panic!("expected InconsistentConfig, got {other:?}"),
        }
    }

    #[test]
    fn for_anchor_is_strict() {
        let config = TrustConfig::for_anchor(anchors::GEM_RCA8);
        assert_eq!(config.revocation, RevocationMode::HardFail);
        assert!(!config.accept_test_only_policies);
        assert!(!config.allow_expired);
        assert_eq!(config.roots_url, roots::URL_PROD);
        assert_eq!(config.tsl_url, tsl::URL_PROD);
        assert!(config.roots.is_empty());
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn preset_prod_validates_for_prod() {
        TrustConfig::preset_prod().validate(Tier::Prod).unwrap();
    }

    #[cfg(not(feature = "brainpool"))]
    #[test]
    fn preset_prod_needs_brainpool() {
        assert_eq!(
            reason(TrustConfig::preset_prod().validate(Tier::Prod)),
            "no configured signature algorithm handles the anchor's key type"
        );
    }

    #[test]
    fn nist_config_validates_for_prod() {
        nist_prod_config().validate(Tier::Prod).unwrap();
    }

    #[test]
    fn anchor_without_a_matching_algorithm_is_rejected() {
        let nist_only = TrustConfig {
            algorithms: Cow::Borrowed(algorithms::STANDARD),
            ..TrustConfig::preset_prod()
        };
        assert_eq!(
            reason(nist_only.validate(Tier::NonProd)),
            "no configured signature algorithm handles the anchor's key type"
        );
    }

    #[test]
    fn default_algorithms_are_configured() {
        let config = TrustConfig::for_anchor(anchors::GEM_RCA8);
        assert_eq!(config.algorithms.len(), algorithms::DEFAULT.len());
    }

    #[test]
    fn soft_fail_is_rejected_in_prod() {
        let config = TrustConfig {
            revocation: RevocationMode::SoftFail,
            ..nist_prod_config()
        };
        assert_eq!(
            reason(config.validate(Tier::Prod)),
            "production requires HardFail revocation"
        );
        config.validate(Tier::NonProd).unwrap();
    }

    #[test]
    fn relaxations_are_rejected_in_prod() {
        let test_only = TrustConfig {
            accept_test_only_policies: true,
            ..nist_prod_config()
        };
        assert!(test_only.validate(Tier::Prod).is_err());
        let expired = TrustConfig {
            allow_expired: true,
            ..nist_prod_config()
        };
        assert!(expired.validate(Tier::Prod).is_err());
    }

    #[test]
    fn plain_http_tsl_is_rejected() {
        let config = TrustConfig {
            tsl_url: Cow::Borrowed("http://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml"),
            ..nist_prod_config()
        };
        assert_eq!(
            reason(config.validate(Tier::NonProd)),
            "tsl_url must be an https URL"
        );
    }

    #[test]
    fn garbage_anchor_is_a_der_error() {
        let config = TrustConfig::for_anchor(&b"not a certificate"[..]);
        assert!(matches!(config.validate(Tier::NonProd), Err(Error::Der(_))));
    }

    #[cfg(all(feature = "dangerous-nonprod", feature = "brainpool"))]
    #[test]
    fn nonprod_presets_are_fenced_from_prod() {
        let test = TrustConfig::preset(Env::Test);
        assert_eq!(
            reason(test.validate(Tier::Prod)),
            "TEST-ONLY anchor in production"
        );
        test.validate(Tier::NonProd).unwrap();
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn test_only_anchor_is_rejected_in_prod_even_when_strict() {
        let config = TrustConfig::for_anchor(anchors::GEM_RCA7_TEST_ONLY);
        assert_eq!(
            reason(config.validate(Tier::Prod)),
            "TEST-ONLY anchor in production"
        );
    }

    #[cfg(all(feature = "dangerous-nonprod", feature = "brainpool"))]
    #[test]
    fn nonprod_presets_accept_test_only_policies() {
        for env in [Env::Dev, Env::Test, Env::Ref] {
            let config = TrustConfig::preset(env);
            assert!(config.accept_test_only_policies, "{env}");
            assert_eq!(config.revocation, RevocationMode::HardFail, "{env}");
            config.validate(Tier::NonProd).unwrap();
        }
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn preset_maps_environments_like_gempki() {
        assert_eq!(TrustConfig::preset(Env::Prod).anchor, anchors::GEM_RCA8);
        assert_eq!(
            TrustConfig::preset(Env::Test).anchor,
            anchors::GEM_RCA8_TEST_ONLY
        );
        for env in [Env::Ref, Env::Dev] {
            let config = TrustConfig::preset(env);
            assert_eq!(config.anchor, anchors::GEM_RCA7_TEST_ONLY, "{env}");
            assert_eq!(config.roots_url, roots::URL_REF, "{env}");
            assert_eq!(config.tsl_url, tsl::URL_REF, "{env}");
        }
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn lab_ca_is_nonprod_only() {
        let anchor = nist_prod_config().anchor;
        let config = TrustConfig::for_lab_ca(&anchor);
        config.validate(Tier::NonProd).unwrap();
        assert!(config.validate(Tier::Prod).is_err());
    }
}
