//! X.509 certificate validation against the rules of the gematik
//! Telematikinfrastruktur (TI) PKI: chains built through the intermediates the
//! TSL publishes up to gematik's root anchors, RFC 5280 path checks, OCSP
//! revocation, and the role-OID and certificate-policy requirements
//! gemSpec_OID attaches to each certificate type, packaged as named profiles
//! for the common TI use cases.
//!
//! # Quick start
//!
//! Validating an SMC-B certificate of the reference environment offline, with the
//! profile picked from the certificate. In production, use [`TrustConfig::preset_prod`]
//! (whose revocation is HardFail), the TSL's intermediates ([`tsl`]) and an
//! [`ocsp::OcspChecker`] (feature `load`) in place of [`revocation::Unchecked`].
//!
//! ```
//! # #[cfg(all(feature = "dangerous-nonprod", feature = "brainpool"))]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//!
//! use ti_pki::revocation::{RevocationMode, Unchecked};
//! use ti_pki::{Env, Tier, Timestamp, TrustConfig, profile, roots};
//!
//! let config = TrustConfig {
//!     revocation: RevocationMode::Disabled,
//!     ..TrustConfig::preset(Env::Ref)
//! };
//! config.validate(Tier::NonProd)?;
//! let now = Timestamp::parse_rfc3339("2026-06-01T00:00:00Z").unwrap();
//! let store = Arc::new(roots::load(&config, now)?.store());
//!
//! // The end entity first, then its CA; normally the CA comes from the TSL.
//! let pem = [
//!     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/admission-1.pem")),
//!     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/smcb-ca51-test-only.pem")),
//! ]
//! .concat();
//! let certs = ti_pki::parse_pem_certificates(pem.as_bytes())?;
//!
//! let selection = profile::select_for_cert(&certs[0]);
//! let (Some(profile), Some(cert_type)) = (selection.profile, selection.cert_type) else {
//!     return Err(format!("no profile: {}", selection.detail).into());
//! };
//! assert_eq!((profile.name, cert_type.as_str()), ("smb-aut", "C.HCI.AUT"));
//!
//! let validator = profile.validator(&config, store, cert_type);
//! let result = futures_lite::future::block_on(validator.validate(&certs, now, &Unchecked))?;
//! assert!(result.valid, "{:?}", result.errors);
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "dangerous-nonprod", feature = "brainpool")))]
//! # fn main() {}
//! ```
//!
//! # Trust anchors
//!
//! Trust starts at one root certificate per environment, compiled into the
//! crate ([`anchors`]). Every other root in a [`TrustStore`] earns its place by
//! chaining back to the anchor through the A_28419 cross-certificate protocol
//! ([`roots`]). The TSL is not a trust source and is not authenticated: it
//! supplies candidate intermediates, of which only those a root signed are kept
//! ([`tsl`]); trust still flows from the anchor.
//!
//! # Validation
//!
//! A [`Validator`] runs chain building ([`chain`], topology only), path
//! validation ([`path`], RFC 5280 §6 plus the end-entity checks), the gemSpec_Krypt
//! key check ([`key`]) and the revocation check for the end entity and every CA
//! ([`revocation`], [`ocsp`]), and folds every finding into one result, each error
//! carrying an [`ErrorCode`] ([`validate`]). [`trustdomain`] tells production from
//! test certificates before a configuration is chosen.
//!
//! # Profiles and types
//!
//! [`CertificateType`] is the gemSpec_PKI Tab_PKI_405 type with the baseline
//! every certificate of that type must satisfy ([`cert_type`]). A profile is a
//! validation strategy for one TI use case: the types it accepts, its
//! revocation strictness, and optionally the admission role that identifies
//! it ([`profile`]).
//!
//! # Environments
//!
//! Everything that differs between environments is a field of [`TrustConfig`]:
//! the anchor, the roots, the TSL location and the policy relaxations. [`Env`]
//! only picks a preset, and [`TrustConfig::validate`] fences production
//! ([`Tier::Prod`]) from non-production material. Presets for non-production
//! environments exist only with the `dangerous-nonprod` feature ([`config`]).
//!
//! # Signature algorithms
//!
//! Signatures are verified through [`rustls_pki_types::SignatureVerificationAlgorithm`]
//! implementations picked from [`TrustConfig::algorithms`]; [`algorithms`] holds the
//! built-in sets, with brainpool behind its own (default) feature.
//!
//! # Loading
//!
//! With the `load` feature, `load` fetches, caches, verifies and hot-reloads roots.json
//! and the TSL through pluggable loaders; the `reqwest` and `tokio` features add a
//! transport and a background driver.

pub mod admission;
pub mod algorithms;
pub mod anchors;
pub mod cert;
pub mod cert_type;
pub mod chain;
pub mod checks;
pub mod config;
pub mod error;
pub mod key;
#[cfg(feature = "load")]
pub mod load;
pub mod ocsp;
pub mod oid;
pub mod path;
pub mod profile;
#[cfg(feature = "reqwest")]
pub mod reqwest;
pub mod revocation;
pub mod roots;
#[cfg(all(test, feature = "brainpool"))]
mod testing;
pub mod time;
#[cfg(feature = "tokio")]
pub mod tokio;
pub mod trustdomain;
pub mod truststore;
pub mod tsl;
pub mod validate;

pub use cert::{Certificate, parse_pem_certificates};
pub use cert_type::{CertificateType, detect_certificate_type};
pub use chain::build_chain;
pub use checks::CertificateCheck;
pub use config::TrustConfig;
pub use error::{Error, ErrorCode, ValidationError, ValidationWarning};
pub use path::{PathOptions, validate_path};
pub use revocation::{RevocationChecker, RevocationMode, RevocationResult, RevocationStatus};
pub use ti_types::{Env, Tier};
pub use time::{Clock, Timestamp};
pub use truststore::TrustStore;
pub use validate::{CertResult, ChainPosition, ValidationResult, Validator};
