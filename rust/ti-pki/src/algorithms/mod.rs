//! Signature algorithms, plugged in through one trait.
//!
//! Every signature `ti-pki` checks (the cross-certificate walk, the TSL, certificate
//! chains, OCSP responses) goes through
//! [`rustls_pki_types::SignatureVerificationAlgorithm`]: the verifier is chosen by the
//! exact pair of the key's `subjectPublicKeyInfo` algorithm and the signature algorithm,
//! as in webpki. Validation code never names a curve. A configuration carries its set in
//! [`TrustConfig::algorithms`](crate::TrustConfig::algorithms).
//!
//! - [`STANDARD`]: ECDSA on NIST P-256 / SHA-256 and P-384 / SHA-384 (RustCrypto).
//! - [`brainpool`] (feature `brainpool`, on by default): ECDSA on brainpoolP256r1 /
//!   SHA-256 and brainpoolP384r1 / SHA-384 (RustCrypto `bp256`/`bp384`). The TI's
//!   anchors are brainpool keys.
//! - [`rsa`] (feature `rsa`, on by default): RSA PKCS#1 v1.5 and PSS with SHA-256,
//!   SHA-384 and SHA-512 (RustCrypto `rsa`). The historical roots GEM.RCA2/6/9 are RSA
//!   keys, so the cross-certificate walk needs it to reach the roots behind them.
//! - [`DEFAULT`]: what the presets use; `STANDARD` plus brainpool and RSA when enabled.
//!
//! Anything else — FIPS-validated implementations such as webpki's aws-lc-rs set,
//! ML-DSA later — plugs in the same way, as further implementations of the trait in the
//! configuration's set. The implementations here are pure Rust and build for wasm32.
//!

use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

#[cfg(feature = "brainpool")]
pub mod brainpool;
#[cfg(feature = "rsa")]
pub mod rsa;

/// A set of algorithms, in the form [`TrustConfig::algorithms`](crate::TrustConfig::algorithms) holds.
pub type AlgorithmSet = [&'static dyn SignatureVerificationAlgorithm];

/// ECDSA on NIST P-256 with SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "ECDSA P-256 SHA-256",
    public_key_alg_id: rustls_pki_types::alg_id::ECDSA_P256,
    signature_alg_id: rustls_pki_types::alg_id::ECDSA_SHA256,
    verify: p256_sha256,
};

/// ECDSA on NIST P-384 with SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "ECDSA P-384 SHA-384",
    public_key_alg_id: rustls_pki_types::alg_id::ECDSA_P384,
    signature_alg_id: rustls_pki_types::alg_id::ECDSA_SHA384,
    verify: p384_sha384,
};

/// The NIST curves.
pub static STANDARD: &AlgorithmSet = &[ECDSA_P256_SHA256, ECDSA_P384_SHA384];

/// The presets' set: [`STANDARD`], plus [`brainpool::ALL`] and [`rsa::ALL`] with their
/// (default) features.
#[cfg(all(feature = "brainpool", feature = "rsa"))]
pub static DEFAULT: &AlgorithmSet = &[
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    brainpool::ECDSA_BP256R1_SHA256,
    brainpool::ECDSA_BP384R1_SHA384,
    rsa::RSA_PKCS1_SHA256,
    rsa::RSA_PKCS1_SHA384,
    rsa::RSA_PKCS1_SHA512,
    rsa::RSA_PSS_SHA256,
    rsa::RSA_PSS_SHA384,
    rsa::RSA_PSS_SHA512,
];

/// The presets' set: [`STANDARD`] plus [`brainpool::ALL`].
#[cfg(all(feature = "brainpool", not(feature = "rsa")))]
pub static DEFAULT: &AlgorithmSet = &[
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    brainpool::ECDSA_BP256R1_SHA256,
    brainpool::ECDSA_BP384R1_SHA384,
];

/// The presets' set: [`STANDARD`] plus [`rsa::ALL`].
#[cfg(all(not(feature = "brainpool"), feature = "rsa"))]
pub static DEFAULT: &AlgorithmSet = &[
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    rsa::RSA_PKCS1_SHA256,
    rsa::RSA_PKCS1_SHA384,
    rsa::RSA_PKCS1_SHA512,
    rsa::RSA_PSS_SHA256,
    rsa::RSA_PSS_SHA384,
    rsa::RSA_PSS_SHA512,
];

/// The presets' set: [`STANDARD`] only.
#[cfg(not(any(feature = "brainpool", feature = "rsa")))]
pub static DEFAULT: &AlgorithmSet = STANDARD;

/// The algorithm in `set` for a key with `public_key_alg_id` and a signature with
/// `signature_alg_id`, both the DER contents of the respective `AlgorithmIdentifier`
/// (without the outer SEQUENCE).
pub fn find(
    set: &AlgorithmSet,
    public_key_alg_id: &[u8],
    signature_alg_id: &[u8],
) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    set.iter().copied().find(|alg| {
        alg.public_key_alg_id().as_ref() == public_key_alg_id
            && alg.signature_alg_id().as_ref() == signature_alg_id
    })
}

/// Whether any algorithm in `set` accepts keys with `public_key_alg_id`.
pub fn supports_key(set: &AlgorithmSet, public_key_alg_id: &[u8]) -> bool {
    set.iter()
        .any(|alg| alg.public_key_alg_id().as_ref() == public_key_alg_id)
}

/// `verify_signature` of one curve and hash: (public key, message, signature).
pub(crate) type VerifyFn = fn(&[u8], &[u8], &[u8]) -> Result<(), InvalidSignature>;

/// One built-in algorithm: fixed identifiers and a verify function over a RustCrypto
/// backend.
pub(crate) struct Builtin {
    pub(crate) name: &'static str,
    pub(crate) public_key_alg_id: AlgorithmIdentifier,
    pub(crate) signature_alg_id: AlgorithmIdentifier,
    pub(crate) verify: VerifyFn,
}

impl core::fmt::Debug for Builtin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name)
    }
}

impl SignatureVerificationAlgorithm for Builtin {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        (self.verify)(public_key, message, signature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

/// Defines `fn $name(public_key, message, signature)`: SEC1 key (checked to be a point on
/// the curve), DER `ECDSA-Sig-Value`, message hashed with the curve's digest.
macro_rules! ecdsa_verify_fn {
    ($name:ident, $curve:ty) => {
        fn $name(
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), rustls_pki_types::InvalidSignature> {
            use ecdsa::signature::Verifier as _;
            let key = ecdsa::VerifyingKey::<$curve>::from_sec1_bytes(public_key)
                .map_err(|_| rustls_pki_types::InvalidSignature)?;
            let signature = ecdsa::Signature::<$curve>::from_der(signature)
                .map_err(|_| rustls_pki_types::InvalidSignature)?;
            key.verify(message, &signature)
                .map_err(|_| rustls_pki_types::InvalidSignature)
        }
    };
}
#[cfg(feature = "brainpool")]
pub(crate) use ecdsa_verify_fn;

ecdsa_verify_fn!(p256_sha256, p256::NistP256);
ecdsa_verify_fn!(p384_sha384, p384::NistP384);

#[cfg(test)]
pub(crate) mod tests {
    use base64ct::{Base64, Encoding};
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    use super::*;

    /// Key algorithm, signature algorithm (both as `find` takes them), key, signed bytes,
    /// signature.
    pub(crate) type SignedParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    /// What checking `subject`'s signature by `issuer` takes.
    pub(crate) fn signed_parts(issuer: &Certificate, subject: &Certificate) -> SignedParts {
        let spki = issuer.tbs_certificate().subject_public_key_info();
        (
            contents(&spki.algorithm.to_der().unwrap()),
            contents(&subject.signature_algorithm().to_der().unwrap()),
            spki.subject_public_key.raw_bytes().to_vec(),
            subject.tbs_certificate().to_der().unwrap(),
            subject.signature().raw_bytes().to_vec(),
        )
    }

    fn contents(sequence: &[u8]) -> Vec<u8> {
        der::asn1::AnyRef::from_der(sequence)
            .unwrap()
            .value()
            .to_vec()
    }

    /// Verifies `subject`'s signature by `issuer` through `set`.
    pub(crate) fn verify_with(
        set: &AlgorithmSet,
        issuer: &Certificate,
        subject: &Certificate,
    ) -> Result<(), &'static str> {
        let (key_alg, sig_alg, key, tbs, sig) = signed_parts(issuer, subject);
        let alg = find(set, &key_alg, &sig_alg).ok_or("no algorithm")?;
        alg.verify_signature(&key, &tbs, &sig)
            .map_err(|_| "invalid signature")
    }

    /// The root named `cn` from the embedded production roots.json, and its cross
    /// certificates.
    pub(crate) fn prod_root(cn: &str) -> (Certificate, Option<Certificate>, Option<Certificate>) {
        let roots: serde_json::Value = serde_json::from_slice(crate::roots::ROOTS_PROD).unwrap();
        let entry = roots
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["cn"] == cn)
            .unwrap();
        let cert = |field: &str| {
            entry[field]
                .as_str()
                .map(|b64| Certificate::from_der(&Base64::decode_vec(b64).unwrap()).unwrap())
        };
        (cert("cert").unwrap(), cert("next"), cert("prev"))
    }

    #[test]
    fn nist_p256_root_self_signature() {
        let (rca10, _, _) = prod_root("GEM.RCA10");
        assert_eq!(verify_with(STANDARD, &rca10, &rca10), Ok(()));
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (rca10, _, _) = prod_root("GEM.RCA10");
        let (key_alg, sig_alg, key, mut tbs, sig) = signed_parts(&rca10, &rca10);
        tbs[40] ^= 1;
        let alg = find(STANDARD, &key_alg, &sig_alg).unwrap();
        assert!(alg.verify_signature(&key, &tbs, &sig).is_err());
    }

    #[test]
    fn garbage_key_and_signature_are_rejected() {
        let (rca10, _, _) = prod_root("GEM.RCA10");
        let (_, _, key, tbs, sig) = signed_parts(&rca10, &rca10);
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&key[..10], &tbs, &sig)
                .is_err()
        );
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&key, &tbs, &sig[..10])
                .is_err()
        );
        assert!(
            ECDSA_P384_SHA384
                .verify_signature(&key, &tbs, &sig)
                .is_err()
        );
    }

    #[test]
    fn find_matches_the_exact_pair() {
        let (rca10, _, _) = prod_root("GEM.RCA10");
        let (key_alg, sig_alg, ..) = signed_parts(&rca10, &rca10);
        assert!(find(STANDARD, &key_alg, &sig_alg).is_some());
        let sha384 = rustls_pki_types::alg_id::ECDSA_SHA384;
        assert!(find(STANDARD, &key_alg, sha384.as_ref()).is_none());
        assert!(supports_key(STANDARD, &key_alg));
    }
}
