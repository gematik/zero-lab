//! The set of root certificates a chain must end in. A trust store is
//! immutable once built and safe to share across threads; refreshing trust
//! means building a new store and swapping it in. Intermediate CAs are never
//! part of it: they come from the TSL or from the candidate chain.

use crate::Certificate;

/// An immutable set of trusted root certificates, each of which either is an
/// environment's anchor or chains back to it (see [`crate::roots`]).
///
/// There is no key-type gate: whoever assembles the roots has already decided what to
/// trust; the store only deduplicates and indexes.
#[derive(Clone, Debug)]
pub struct TrustStore {
    roots: Vec<Certificate>,
}

impl TrustStore {
    /// A store over `roots`, in order. A root whose subject key identifier (or, without
    /// one, whose encoding) appeared earlier is dropped; the first occurrence wins.
    /// Roots sharing a common name but not a key coexist; [`by_common_name`] returns
    /// the first, so prefer [`by_ski`] where a key identifier is at hand.
    ///
    /// [`by_common_name`]: Self::by_common_name
    /// [`by_ski`]: Self::by_ski
    pub fn new(roots: impl IntoIterator<Item = Certificate>) -> Self {
        let mut unique: Vec<Certificate> = Vec::new();
        for root in roots {
            let duplicate =
                unique.iter().any(
                    |seen| match (seen.subject_key_id(), root.subject_key_id()) {
                        (Some(a), Some(b)) => a == b,
                        _ => seen == &root,
                    },
                );
            if !duplicate {
                unique.push(root);
            }
        }
        TrustStore { roots: unique }
    }

    /// The trusted roots, in the order they were added.
    pub fn roots(&self) -> &[Certificate] {
        &self.roots
    }

    /// The first root with common name `cn`.
    pub fn by_common_name(&self, cn: &str) -> Option<&Certificate> {
        self.roots.iter().find(|root| root.subject_cn() == cn)
    }

    /// The root with subject key identifier `ski`. Preferred over the common name,
    /// which is not unique across a rollover.
    pub fn by_ski(&self, ski: &[u8]) -> Option<&Certificate> {
        self.roots
            .iter()
            .find(|root| root.subject_key_id() == Some(ski))
    }

    /// Whether `cert` is one of the roots.
    pub fn contains(&self, cert: &Certificate) -> bool {
        self.roots.contains(cert)
    }

    /// The number of distinct roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

#[cfg(feature = "load")]
impl TrustStore {
    pub(crate) fn from_verified(verified: crate::load::Verified) -> Self {
        TrustStore::new(verified.roots)
    }
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::cert::tests::{RCA2_RSA, fixture};
    use crate::testing::TestPki;

    #[test]
    fn dedup_and_lookup() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone(), pki.rca7.clone(), pki.rca1.clone()]);
        assert_eq!(store.len(), 2, "duplicate SKI must dedupe");
        assert_eq!(store.by_common_name("GEM.RCA1 TEST-ONLY"), Some(&pki.rca1));
        assert_eq!(
            store.by_ski(pki.rca7.subject_key_id().unwrap()),
            Some(&pki.rca7)
        );
        assert!(store.contains(&pki.rca7));
        assert!(!store.contains(&pki.rogue_root));
        assert_eq!(store.by_common_name("nobody"), None);
        assert_eq!(store.by_ski(b"nothing"), None);
    }

    #[test]
    fn accepts_rsa_roots() {
        let rsa = fixture(RCA2_RSA);
        let store = TrustStore::new([rsa.clone()]);
        assert_eq!(store.by_common_name("GEM.RCA2 TEST-ONLY"), Some(&rsa));
    }
}
