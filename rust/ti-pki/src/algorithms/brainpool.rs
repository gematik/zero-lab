//! ECDSA on the Brainpool curves (RFC 5639), over RustCrypto `bp256` / `bp384`.
//!
//! Isolated behind the `brainpool` feature: nothing else in the crate refers to these
//! items except [`DEFAULT`](super::DEFAULT). Verification handles public data only, so
//! timing does not matter here; correctness is covered by the Wycheproof vectors and the
//! real TI roots in the tests.

use rustls_pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm, alg_id};

use super::{Builtin, ecdsa_verify_fn};

/// `id-ecPublicKey` with `brainpoolP256r1` (1.3.36.3.3.2.8.1.1.7), as the DER contents of
/// the `AlgorithmIdentifier`.
pub const BRAINPOOL_P256R1: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, // brainpoolP256r1
]);

/// `id-ecPublicKey` with `brainpoolP384r1` (1.3.36.3.3.2.8.1.1.11), as the DER contents
/// of the `AlgorithmIdentifier`.
pub const BRAINPOOL_P384R1: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b, // brainpoolP384r1
]);

/// ECDSA on brainpoolP256r1 with SHA-256; what the TI roots and CAs sign with.
pub static ECDSA_BP256R1_SHA256: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "ECDSA brainpoolP256r1 SHA-256",
    public_key_alg_id: BRAINPOOL_P256R1,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verify: bp256r1_sha256,
};

/// ECDSA on brainpoolP384r1 with SHA-384.
pub static ECDSA_BP384R1_SHA384: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "ECDSA brainpoolP384r1 SHA-384",
    public_key_alg_id: BRAINPOOL_P384R1,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verify: bp384r1_sha384,
};

/// Both Brainpool algorithms.
pub static ALL: &super::AlgorithmSet = &[ECDSA_BP256R1_SHA256, ECDSA_BP384R1_SHA384];

ecdsa_verify_fn!(bp256r1_sha256, bp256::BrainpoolP256r1);
ecdsa_verify_fn!(bp384r1_sha384, bp384::BrainpoolP384r1);

#[cfg(test)]
mod tests {
    use der::Decode;
    use x509_cert::Certificate;

    use super::*;
    use crate::algorithms::tests::{prod_root, signed_parts, verify_with};
    use crate::algorithms::{DEFAULT, STANDARD};

    fn rca8() -> Certificate {
        Certificate::from_der(crate::anchors::GEM_RCA8).unwrap()
    }

    #[test]
    fn identifiers_match_the_prod_anchor() {
        let anchor = rca8();
        let (key_alg, sig_alg, ..) = signed_parts(&anchor, &anchor);
        assert_eq!(key_alg, BRAINPOOL_P256R1.as_ref());
        assert_eq!(sig_alg, alg_id::ECDSA_SHA256.as_ref());
    }

    #[test]
    fn prod_anchor_self_signature() {
        let anchor = rca8();
        assert_eq!(verify_with(ALL, &anchor, &anchor), Ok(()));
        assert_eq!(verify_with(STANDARD, &anchor, &anchor), Err("no algorithm"));
    }

    #[test]
    fn prod_anchor_signs_its_cross_certificates() {
        let anchor = rca8();
        let (_, next, prev) = prod_root("GEM.RCA8");
        // RCA8 → RCA9 (an RSA root) and RCA8 → RCA7 (a P-256 root): both signed with
        // the brainpool key.
        assert_eq!(verify_with(DEFAULT, &anchor, &next.unwrap()), Ok(()));
        assert_eq!(verify_with(DEFAULT, &anchor, &prev.unwrap()), Ok(()));
    }

    #[test]
    fn signature_by_the_wrong_root_is_rejected() {
        let (rca3, _, _) = prod_root("GEM.RCA3");
        assert_eq!(verify_with(ALL, &rca3, &rca8()), Err("invalid signature"));
    }
}
