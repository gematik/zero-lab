//! RSA signatures (PKCS#1 v1.5 and PSS with SHA-256, SHA-384, SHA-512) over RustCrypto
//! `rsa`, behind the `rsa` feature.
//!
//! The TI's historical roots GEM.RCA2/6/9 are RSA keys, and RSA end-entity keys are
//! still admissible (gemSpec_Krypt); without RSA the cross-certificate walk cannot pass
//! those roots, and most of the TI's roots stay unreachable.
//!
//! RUSTSEC-2023-0071 (the Marvin timing attack) is open against every `rsa` release. It
//! concerns operations with the private key; verification handles public data only, so
//! the advisory is ignored for this crate in `deny.toml` and `.cargo/audit.toml`. The
//! crate is at a release candidate (0.10.0-rc), the only line on the current RustCrypto
//! stack; see `docs/development.md`, "Known compromises".

use digest::{Digest, FixedOutputReset, const_oid::AssociatedOid};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier;
use rustls_pki_types::{InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use sha2::{Sha256, Sha384, Sha512};

use super::Builtin;

/// RSA PKCS#1 v1.5 with SHA-256; the TI's RSA roots and CAs sign with it.
pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PKCS#1 v1.5 SHA-256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    verify: pkcs1::<Sha256>,
};

/// RSA PKCS#1 v1.5 with SHA-384.
pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PKCS#1 v1.5 SHA-384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verify: pkcs1::<Sha384>,
};

/// RSA PKCS#1 v1.5 with SHA-512.
pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PKCS#1 v1.5 SHA-512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    verify: pkcs1::<Sha512>,
};

/// RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt.
pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PSS SHA-256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    verify: pss::<Sha256>,
};

/// RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt.
pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PSS SHA-384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    verify: pss::<Sha384>,
};

/// RSASSA-PSS with SHA-512, MGF1 with SHA-512 and a 64-byte salt.
pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &Builtin {
    name: "RSA PSS SHA-512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    verify: pss::<Sha512>,
};

/// All RSA algorithms.
pub static ALL: &super::AlgorithmSet = &[
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
];

fn pkcs1<D: Digest + AssociatedOid>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key = RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
    rsa::pkcs1v15::VerifyingKey::<D>::new(key)
        .verify(message, &signature)
        .map_err(|_| InvalidSignature)
}

/// The salt length is the hash length, as the PSS identifiers in `rustls-pki-types`
/// (and RFC 8017's recommendation) fix it.
fn pss<D: Digest + FixedOutputReset>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key = RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
    let signature = rsa::pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
    rsa::pss::VerifyingKey::<D>::new_with_salt_len(key, <D as Digest>::output_size())
        .verify(message, &signature)
        .map_err(|_| InvalidSignature)
}
