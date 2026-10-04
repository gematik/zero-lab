//! The set of root certificates a chain must end in, with the intermediates known to
//! chain to them. A trust store is immutable once built and safe to share across
//! threads; refreshing trust means building a new store and swapping it in.
//! Intermediates are never trust anchors: they only help build a chain, which path
//! validation then checks up to a root.

use const_oid::ObjectIdentifier;

use crate::Certificate;
use crate::tsl::Intermediate;

/// An immutable set of trusted root certificates, each of which either is an
/// environment's anchor or chains back to it (see [`crate::roots`]).
///
/// There is no key-type gate: whoever assembles the roots has already decided what to
/// trust; the store only deduplicates and indexes.
#[derive(Clone, Debug)]
pub struct TrustStore {
    roots: Vec<Certificate>,
    intermediates: Vec<Certificate>,
    /// The TSP of `intermediates[i]`, same index.
    providers: Vec<String>,
    /// OCSP responder certificates a verified TSL lists, with their TSP.
    listed_responders: Vec<(Certificate, String)>,
    /// The certificate types a verified TSL states for its CAs; `None` without a
    /// verified TSL.
    ca_types: Option<Vec<(Certificate, Vec<ObjectIdentifier>)>>,
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
        TrustStore {
            roots: unique,
            intermediates: Vec::new(),
            providers: Vec::new(),
            listed_responders: Vec::new(),
            ca_types: None,
        }
    }

    /// The store with `intermediates` as the candidates chain building draws on,
    /// typically the TSL's CAs as kept by [`tsl::match_to_roots`](crate::tsl::match_to_roots).
    #[must_use]
    pub fn with_intermediates(mut self, intermediates: Vec<Intermediate>) -> Self {
        (self.intermediates, self.providers) = intermediates
            .into_iter()
            .map(|i| (i.certificate, i.provider))
            .unzip();
        self
    }

    /// The OCSP responders a verified TSL lists. Only the loader sets them, from a TSL
    /// whose signature and signer verified.
    #[must_use]
    #[cfg(any(feature = "load", all(test, feature = "brainpool")))]
    pub(crate) fn with_listed_responders(mut self, responders: Vec<(Certificate, String)>) -> Self {
        self.listed_responders = responders;
        self
    }

    /// The certificate types a verified TSL states for its CAs. Only the loader sets
    /// them, from a TSL whose signature and signer verified.
    #[must_use]
    #[cfg(any(feature = "load", all(test, feature = "brainpool")))]
    pub(crate) fn with_ca_types(
        mut self,
        types: Vec<(Certificate, Vec<ObjectIdentifier>)>,
    ) -> Self {
        self.ca_types = Some(types);
        self
    }

    /// The certificate types (Tab_PKI_405 OIDs) the verified TSL lets `ca` issue
    /// (TUC_PKI_007): `None` without a verified TSL, or if it does not list `ca` or states
    /// no types for it.
    pub fn tsl_types_of(&self, ca: &Certificate) -> Option<&[ObjectIdentifier]> {
        self.ca_types
            .as_ref()?
            .iter()
            .find(|(listed, types)| listed == ca && !types.is_empty())
            .map(|(_, types)| types.as_slice())
    }

    /// Whether the store holds the certificate types of a verified TSL.
    pub fn has_tsl_types(&self) -> bool {
        self.ca_types.is_some()
    }

    /// The TSPs under which a verified TSL lists `responder` as an OCSP service; the
    /// certificates must be identical.
    pub fn listed_responder_tsps<'a>(
        &'a self,
        responder: &'a Certificate,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.listed_responders
            .iter()
            .filter(move |(listed, _)| listed == responder)
            .map(|(_, tsp)| tsp.as_str())
    }

    /// The intermediates set with [`with_intermediates`](Self::with_intermediates).
    pub fn intermediates(&self) -> &[Certificate] {
        &self.intermediates
    }

    /// The TSP an intermediate is listed under; `None` for a certificate that is not
    /// one of the intermediates, such as a root.
    pub fn provider_of(&self, cert: &Certificate) -> Option<&str> {
        self.intermediates
            .iter()
            .position(|c| c == cert)
            .map(|i| self.providers[i].as_str())
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
            .with_intermediates(verified.intermediates)
            .with_listed_responders(verified.ocsp_responders)
            .with_ca_types(verified.ca_types)
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
