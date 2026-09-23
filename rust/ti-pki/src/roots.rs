//! Assembly of a [`TrustStore`](crate::TrustStore) from gematik's roots.json,
//! either the copy compiled into the crate or a freshly downloaded one. Every
//! candidate root must chain back to the environment's anchor through the
//! A_28419 cross-certificate protocol: seven checks per candidate, implemented
//! step by step so the code can be read against gemSpec_PKI. The walk follows
//! the anchor's successors forward and its predecessors backward, so a
//! download can only ever add roots that chain to the anchor.

/// Download point of the production roots.json.
pub const URL_PROD: &str = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// Download point of the reference roots.json, which the development environment shares.
pub const URL_REF: &str = "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// Download point of the test roots.json.
pub const URL_TEST: &str = "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// gematik's roots.json for production, as published.
pub const ROOTS_PROD: &[u8] = include_bytes!("roots-prod.json");

/// gematik's roots.json for the non-production environments. test and ref publish
/// the same file, so one copy serves dev, ref and test.
#[cfg(feature = "dangerous-nonprod")]
pub const ROOTS_NONPROD: &[u8] = include_bytes!("roots-nonprod.json");

/// Verifies roots.json against `anchor` with the A_28419 cross-certificate walk and
/// returns the roots that chain to it.
#[cfg(feature = "load")]
pub(crate) fn verify_roots_json(
    _anchor: &[u8],
    _roots_json: &[u8],
) -> Result<Vec<x509_cert::Certificate>, crate::load::VerifyError> {
    todo!("gempki-port: A_28419 cross-certificate walk from go/gempki/roots.go")
}
