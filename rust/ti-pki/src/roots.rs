//! Assembly of a [`TrustStore`](crate::TrustStore) from gematik's roots.json,
//! either the copy compiled into the crate or a freshly downloaded one. Every
//! candidate root must chain back to the environment's anchor through the
//! A_28419 cross-certificate protocol: seven checks per candidate, implemented
//! step by step so the code can be read against gemSpec_PKI. The walk follows
//! the anchor's successors forward and its predecessors backward, so a
//! download can only ever add roots that chain to the anchor.

/// gematik's roots.json for production, as published.
pub const ROOTS_PROD: &[u8] = include_bytes!("roots-prod.json");

/// gematik's roots.json for the non-production environments. test and ref publish
/// the same file, so one copy serves dev, ref and test.
#[cfg(feature = "dangerous-nonprod")]
pub const ROOTS_NONPROD: &[u8] = include_bytes!("roots-nonprod.json");
