//! X.509 certificate validation against the rules of the gematik
//! Telematikinfrastruktur (TI) PKI: chains built through the intermediates the
//! TSL publishes up to gematik's root anchors, RFC 5280 path checks, OCSP
//! revocation, and the role-OID and certificate-policy requirements
//! gemSpec_OID attaches to each certificate type, packaged as named profiles
//! for the common TI use cases.
//!
//! This crate is a skeleton. The module layout and the types below are fixed;
//! the validation logic is being ported from the Go reference implementation
//! `gempki` in the same repository.
//!
//! # Quick start
//!
//! The intended shape of the API, not yet implemented:
//!
//! ```ignore
//! use ti_pki::{Env, TrustStore, tsl};
//!
//! let ts = TrustStore::embedded(Env::Prod)?;
//! let list = tsl::parse(&tsl_xml)?;
//! let intermediates = tsl::intermediate_cas(&list);
//!
//! let certs = ti_pki::parse_pem_certificates(&pem)?; // leaf first
//! let sel = ti_pki::profile::select_for_cert(&certs[0]); // e.g. smb-aut for a C.HCI.AUT
//! let validator = sel.profile.validator(&ts, sel.cert_type);
//! let result = validator.validate(&certs, &intermediates)?;
//! if !result.valid {
//!     eprintln!("rejected: {:?}", result.errors);
//! }
//! ```
//!
//! # Trust anchors
//!
//! Trust starts at one root certificate per environment, compiled into the
//! crate ([`anchors`]). Every other root in a [`TrustStore`] earns its place by
//! chaining back to the anchor through the A_28419 cross-certificate protocol
//! ([`roots`]). The TSL is not a trust source: it names the SubCAs gematik
//! currently sanctions and the OCSP responders allowed to answer for them
//! ([`tsl`]); trust still flows from the anchor.
//!
//! # Validation
//!
//! A validator runs chain building ([`chain`], topology only), path
//! validation ([`path`], RFC 5280 §6 plus the end-entity checks) and the
//! revocation check ([`revocation`], [`ocsp`]), and folds every finding into
//! one result, each error carrying an [`ErrorCode`] ([`validate`]).
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
//! [`Env`] selects the anchors, the embedded roots and the download endpoints.
//! It is fixed when a trust store is built; nothing reconfigures it at
//! runtime.

pub mod anchors;
pub mod cert_type;
pub mod chain;
pub mod error;
pub mod ocsp;
pub mod oid;
pub mod path;
pub mod profile;
pub mod revocation;
pub mod roots;
pub mod truststore;
pub mod tsl;
pub mod validate;

pub use cert_type::CertificateType;
pub use error::{Error, ErrorCode};
pub use revocation::RevocationMode;
pub use ti_types::{Env, Tier};
pub use truststore::TrustStore;
