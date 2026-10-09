//! ECDH-ES (RFC 7518 §4.6): the one place where JWE agrees on a key. Both sides end in
//! [`concat_kdf`]; the sender also makes the ephemeral key ([`sender`]), the recipient
//! gets Z from its [`KeyAgreement`](crate::keys::KeyAgreement).
//!
//! The KDF works on Z as bytes, so it is the same for every curve; it is written as
//! straight-line arithmetic over a hash so that its functional correctness can be proven
//! against NIST SP 800-56A §5.8.1 (hax, stage S7).

use alloc::vec::Vec;

use crate::crypto::{Backend, Hash, Zeroizing};
use crate::error::{Error, ErrorCode};
use crate::jwa::Curve;

/// The single-step Concat KDF of NIST SP 800-56A §5.8.1 as RFC 7518 §4.6.2 profiles it:
/// `key_len` bytes from `hash(counter || Z || OtherInfo)` for counter = 1, 2, …, where
/// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, each of the first
/// three a 32-bit big-endian length followed by the data, SuppPubInfo the key length in
/// bits as a 32-bit big-endian number, SuppPrivInfo empty.
///
/// # Errors
///
/// [`ErrorCode::InvalidMember`] if a length does not fit the 32-bit fields or `key_len`
/// is zero.
pub fn concat_kdf(
    hash: &dyn Hash,
    z: &[u8],
    algorithm_id: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let too_long = Error::new(ErrorCode::InvalidMember, "concat kdf length");
    // RFC 7518 §4.6.2: keydatalen in bits, as a 32-bit big-endian SuppPubInfo.
    let key_bits = key_len
        .checked_mul(8)
        .and_then(|bits| u32::try_from(bits).ok())
        .filter(|bits| *bits > 0)
        .ok_or(too_long)?;
    let mut other_info = Vec::with_capacity(16 + algorithm_id.len() + apu.len() + apv.len());
    for datum in [algorithm_id, apu, apv] {
        let len = u32::try_from(datum.len()).map_err(|_| too_long)?;
        other_info.extend_from_slice(&len.to_be_bytes());
        other_info.extend_from_slice(datum);
    }
    other_info.extend_from_slice(&key_bits.to_be_bytes());

    let hash_len = hash.algorithm().output_len();
    // reps = ceil(key_len / hash_len); at most key_len, which fits u32 by the check above.
    let reps = key_len.div_ceil(hash_len);
    let mut derived = Zeroizing::new(Vec::with_capacity(reps * hash_len));
    for counter in 1..=reps {
        let counter = u32::try_from(counter).map_err(|_| too_long)?;
        let block = Zeroizing::new(hash.digest(&[&counter.to_be_bytes(), z, &other_info]));
        derived.extend_from_slice(&block);
    }
    derived.truncate(key_len);
    Ok(derived)
}

/// The sender's side: a fresh ephemeral key on `curve`, and Z with the recipient's SEC1
/// point `recipient`. Returns the ephemeral public point (for `epk`) and Z.
///
/// # Errors
///
/// [`ErrorCode::UnsupportedAlgorithm`] without ECDH on `curve`, or the backend's error
/// (an invalid recipient point among them).
pub fn sender(
    backend: &dyn Backend,
    curve: Curve,
    recipient: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let ecdh = backend
        .ecdh(curve)
        .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "ecdh curve"))?;
    let ephemeral = ecdh.generate(backend.rng())?;
    let z = ecdh.agree(&ephemeral.secret, recipient)?;
    Ok((ephemeral.public, z))
}

#[cfg(all(test, feature = "crypto-rustcrypto"))]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::jwa::HashAlgorithm;

    /// RFC 7518 Appendix C: Z, "A128GCM", "Alice", "Bob" → VqqN6vgjbSBcIijNcacQGg.
    #[test]
    fn rfc_7518_appendix_c_concat_kdf() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let backend = RustCrypto::new();
        let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
        let key = concat_kdf(sha256, &z, b"A128GCM", b"Alice", b"Bob", 16).unwrap();
        assert_eq!(
            key.as_slice(),
            [
                86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
            ]
        );
    }

    #[test]
    fn rfc_7518_4_6_2_more_than_one_round_and_zero_length() {
        let backend = RustCrypto::new();
        let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
        let long = concat_kdf(sha256, b"z", b"alg", b"", b"", 48).unwrap();
        assert_eq!(long.len(), 48);
        // The first 32 bytes are round 1 of a 48-byte key, not of a 32-byte key:
        // keydatalen is part of OtherInfo.
        let short = concat_kdf(sha256, b"z", b"alg", b"", b"", 32).unwrap();
        assert_ne!(&long[..32], short.as_slice());
        assert!(concat_kdf(sha256, b"z", b"alg", b"", b"", 0).is_err());
    }
}
