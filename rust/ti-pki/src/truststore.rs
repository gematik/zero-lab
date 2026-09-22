//! The set of root certificates a chain must end in. A trust store is
//! immutable once built and safe to share across threads; refreshing trust
//! means building a new store and swapping it in. Intermediate CAs are never
//! part of it: they come from the TSL or from the candidate chain.

use x509_cert::Certificate;

/// An immutable set of trusted root certificates, each of which either is an
/// environment's anchor or chains back to it (see [`crate::roots`]).
#[derive(Debug, Clone)]
pub struct TrustStore {
    roots: Vec<Certificate>,
}

impl TrustStore {
    /// The trusted roots, anchor first.
    pub fn roots(&self) -> &[Certificate] {
        &self.roots
    }
}
