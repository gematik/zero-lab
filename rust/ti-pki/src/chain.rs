//! Chain construction: walks issuer references from the leaf through the
//! supplied intermediates until it lands on a trust-store root, preferring
//! AuthorityKeyIdentifier matches over issuer-name matches so it works across
//! root rollovers. This is topology only; signatures and validity are the
//! concern of [`path`](crate::path). Length and cycles are bounded, so an
//! adversarial set of intermediates cannot make it run away.

use crate::error::{ErrorCode, ValidationError};
use crate::{Certificate, TrustStore};

/// The most certificates a built chain may hold: end entity, SubCA, a SubSubCA or
/// rollover step, and the root, with headroom. Bounds adversarial constructions.
pub const MAX_CHAIN_LEN: usize = 5;

/// Chain building stopped before reaching a root.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{error}")]
pub struct ChainError {
    /// The chain walked so far, leaf first, ending at the certificate whose issuer could
    /// not be found; what a caller shows to say where the walk stopped.
    pub partial: Vec<Certificate>,
    /// Why, with [`ErrorCode::ChainIncomplete`].
    pub error: ValidationError,
}

/// Walks issuer references from `leaf` through `intermediates` until it reaches a root
/// of `store`, and returns the chain leaf first, root last.
///
/// Topology only: no signatures, no validity; [`validate_path`](crate::path::validate_path)
/// checks those on the result. An issuer is looked up by the authority key identifier
/// where the certificate has one — precise across a rollover in which two roots share a
/// name — and by name otherwise; trust store roots take precedence over intermediates.
///
/// # Errors
///
/// [`ChainError`] with [`ErrorCode::ChainIncomplete`] if no issuer is found, the chain
/// would exceed [`MAX_CHAIN_LEN`], or it loops.
pub fn build_chain(
    leaf: &Certificate,
    intermediates: &[Certificate],
    store: &TrustStore,
) -> Result<Vec<Certificate>, ChainError> {
    let mut chain = vec![leaf.clone()];
    let mut current = leaf.clone();
    let incomplete = |chain: Vec<Certificate>, subject: &str, message: String| ChainError {
        partial: chain,
        error: ValidationError::new(ErrorCode::ChainIncomplete, message).with_subject(subject),
    };
    while chain.len() < MAX_CHAIN_LEN {
        let Some((issuer, is_root)) = find_issuer(&current, intermediates, store) else {
            let message = format!(
                "no issuer found (issuer DN {:?}, AKI {})",
                current.issuer_cn(),
                hex(current.authority_key_id().unwrap_or_default())
            );
            return Err(incomplete(chain, current.subject_cn(), message));
        };
        if is_root {
            chain.push(issuer.clone());
            return Ok(chain);
        }
        if chain.contains(issuer) {
            return Err(incomplete(
                chain,
                issuer.subject_cn(),
                "cycle detected".into(),
            ));
        }
        chain.push(issuer.clone());
        current = issuer.clone();
    }
    Err(incomplete(
        chain,
        current.subject_cn(),
        format!("chain exceeds {MAX_CHAIN_LEN} certificates"),
    ))
}

/// The issuer of `cert`, and whether it is a trust store root.
fn find_issuer<'a>(
    cert: &Certificate,
    intermediates: &'a [Certificate],
    store: &'a TrustStore,
) -> Option<(&'a Certificate, bool)> {
    let root = match cert.authority_key_id() {
        Some(aki) => store.by_ski(aki),
        None => store.by_common_name(cert.issuer_cn()),
    };
    if let Some(root) = root.filter(|root| names_match(cert, root)) {
        return Some((root, true));
    }
    intermediates
        .iter()
        .find(|candidate| {
            names_match(cert, candidate)
                && cert
                    .authority_key_id()
                    .is_none_or(|aki| candidate.subject_key_id() == Some(aki))
        })
        .map(|intermediate| (intermediate, false))
}

/// Whether `cert`'s issuer name is `candidate`'s subject name, compared in their RFC 4514
/// rendering as `gempki` does, so names that differ only in string encoding still match.
fn names_match(cert: &Certificate, candidate: &Certificate) -> bool {
    let (issuer, subject) = (cert.issuer().to_string(), candidate.subject().to_string());
    if issuer.is_empty() || subject.is_empty() {
        return cert.issuer_cn() == candidate.subject_cn();
    }
    issuer == subject
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::testing::TestPki;

    fn cns(chain: &[Certificate]) -> Vec<&str> {
        chain.iter().map(Certificate::subject_cn).collect()
    }

    #[test]
    fn brainpool_chain() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone(), pki.rca7.clone()]);
        let chain = build_chain(
            &pki.ee_arzt,
            &[pki.sub_ca_hba.clone(), pki.sub_ca_komp.clone()],
            &store,
        )
        .unwrap();
        assert_eq!(
            cns(&chain),
            [
                "Dr. Arzt TEST-ONLY",
                "GEM.SubCA-HBA TEST-ONLY",
                "GEM.RCA1 TEST-ONLY"
            ]
        );
    }

    #[test]
    fn nist_and_mixed_curve_chains() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone(), pki.rca7.clone()]);
        let intermediates = [pki.sub_ca_komp.clone(), pki.sub_ca_mixed.clone()];
        let nist = build_chain(&pki.ee_zeta, &intermediates, &store).unwrap();
        assert_eq!(nist.last(), Some(&pki.rca7));
        let mixed = build_chain(&pki.ee_mixed, &intermediates, &store).unwrap();
        assert_eq!(
            cns(&mixed)[1..],
            ["GEM.SubCA-Mixed TEST-ONLY", "GEM.RCA1 TEST-ONLY"]
        );
    }

    #[test]
    fn rogue_root_outside_the_store() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone()]);
        let error =
            build_chain(&pki.ee_rogue, std::slice::from_ref(&pki.rogue_root), &store).unwrap_err();
        assert_eq!(error.error.code, ErrorCode::ChainIncomplete);
        assert_eq!(
            cns(&error.partial),
            ["rogue-ee NOT-VALID", "ROGUE-ROOT NOT-VALID"]
        );
    }

    #[test]
    fn missing_intermediate_reports_where_it_stopped() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone()]);
        let error = build_chain(&pki.ee_arzt, &[], &store).unwrap_err();
        assert_eq!(error.error.code, ErrorCode::ChainIncomplete);
        assert_eq!(error.error.subject, "Dr. Arzt TEST-ONLY");
        assert!(error.error.message.contains("no issuer found"));
        assert_eq!(cns(&error.partial), ["Dr. Arzt TEST-ONLY"]);
    }

    #[test]
    fn deep_chain_within_the_bound() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rca1.clone()]);
        let chain = build_chain(
            &pki.ee_deep,
            &[pki.sub_sub_ca.clone(), pki.sub_ca_pathlen0.clone()],
            &store,
        )
        .unwrap();
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn looping_intermediates_are_a_cycle() {
        let pki = TestPki::new();
        let store = TrustStore::new([pki.rogue_root.clone()]);
        // RCA1 and RCA7 cross-certify each other; neither is in the store.
        let intermediates = [
            pki.cross_rca1_for_rca7.clone(),
            pki.cross_rca7_for_rca1.clone(),
        ];
        let error = build_chain(&pki.sub_ca_komp, &intermediates, &store).unwrap_err();
        assert_eq!(error.error.code, ErrorCode::ChainIncomplete);
        assert!(error.partial.len() <= MAX_CHAIN_LEN);
    }
}
