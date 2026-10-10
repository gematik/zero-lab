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
/// This function checks the lengths and keeps secrets in zeroizing buffers; the
/// arithmetic is the private module `kdf`, the part proven against SP 800-56A in F* (`verification/hax`).
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
    // The 32-bit length prefixes of OtherInfo, and OtherInfo as a whole within usize
    // (on a 32-bit target the prefixes alone do not bound it); kdf::other_info's
    // precondition.
    for datum in [algorithm_id, apu, apv] {
        u32::try_from(datum.len()).map_err(|_| too_long)?;
    }
    algorithm_id
        .len()
        .checked_add(apu.len())
        .and_then(|n| n.checked_add(apv.len()))
        .and_then(|n| n.checked_add(16))
        .ok_or(too_long)?;
    let other_info = kdf::other_info(algorithm_id, apu, apv, key_bits);

    let hash_len = hash.algorithm().output_len();
    // reps = ceil(key_len / hash_len) <= key_len, which fits u32 by the check above.
    let reps = u32::try_from(key_len.div_ceil(hash_len)).map_err(|_| too_long)?;
    // Allocated once at full size: no reallocation leaves a copy of key material behind.
    let mut derived = Zeroizing::new(Vec::with_capacity(key_len.div_ceil(hash_len) * hash_len));
    kdf::rounds(&Backed(hash), z, &other_info, reps, &mut derived);
    derived.truncate(key_len);
    Ok(derived)
}

/// A backend hash as the KDF core's [`kdf::Digest`]; each round's output is wiped once
/// appended.
struct Backed<'a>(&'a dyn Hash);

impl kdf::Digest for Backed<'_> {
    fn append_digest(&self, parts: [&[u8]; 3], out: &mut Vec<u8>) {
        let block = Zeroizing::new(self.0.digest(&parts));
        out.extend_from_slice(&block);
    }
}

/// The arithmetic of the Concat KDF, in the subset of Rust that hax extracts to F*
/// (`just verify-hax-jwz`): no trait objects, no zeroizing wrappers, explicit byte
/// arithmetic. The `ensures` clauses state it equal to the specification transcribed
/// from SP 800-56A §5.8.1 in `verification/hax/Jwz.Kdf.Spec.fst`, and F* proves them.
pub(crate) mod kdf {
    use alloc::vec::Vec;
    #[cfg(hax)]
    use hax_lib::ToInt;

    pub(crate) use digest::Digest;

    /// The hash, in a module of its own so that the F* specification can name it.
    pub(crate) mod digest {
        use alloc::vec::Vec;

        /// A hash function as the KDF sees it: the digest of the concatenated `parts`,
        /// appended to `out`. It is the primitive the proof assumes, not proves.
        #[cfg_attr(hax, hax_lib::attributes)]
        pub(crate) trait Digest {
            #[cfg_attr(hax, hax_lib::requires(true))]
            fn append_digest(&self, parts: [&[u8]; 3], out: &mut Vec<u8>);
        }
    }

    /// `n` as 4 big-endian bytes.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "each byte is taken from its own 8 bits on purpose"
    )]
    #[cfg_attr(
        hax,
        hax_lib::ensures(|result| fstar!("$result == Jwz.Kdf.Spec.be32 (v $n)"))
    )]
    pub(crate) fn be32(n: u32) -> [u8; 4] {
        [(n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }

    /// OtherInfo of RFC 7518 §4.6.2: AlgorithmID, PartyUInfo and PartyVInfo, each a
    /// 32-bit big-endian length and the data, then SuppPubInfo, the key length in bits.
    /// The caller guarantees that every length fits 32 bits.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "concat_kdf checks every length against u32 first"
    )]
    // Each length fits its 32-bit prefix, and the whole of OtherInfo fits usize, which
    // on a 32-bit target (wasm32) the first condition alone does not imply.
    #[cfg_attr(
        hax,
        hax_lib::requires(
            algorithm_id.len() <= u32::MAX as usize
                && apu.len() <= u32::MAX as usize
                && apv.len() <= u32::MAX as usize
                && algorithm_id.len().to_int() + apu.len().to_int() + apv.len().to_int()
                    + hax_lib::int!(16)
                    <= usize::MAX.to_int()
        )
    )]
    #[cfg_attr(
        hax,
        hax_lib::ensures(|result| fstar!(
            "Seq.equal ${result}._0 (Jwz.Kdf.Spec.other_info $algorithm_id $apu $apv (v $key_bits))"
        ))
    )]
    pub(crate) fn other_info(
        algorithm_id: &[u8],
        apu: &[u8],
        apv: &[u8],
        key_bits: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&be32(algorithm_id.len() as u32));
        out.extend_from_slice(algorithm_id);
        out.extend_from_slice(&be32(apu.len() as u32));
        out.extend_from_slice(apu);
        out.extend_from_slice(&be32(apv.len() as u32));
        out.extend_from_slice(apv);
        out.extend_from_slice(&be32(key_bits));
        out
    }

    /// NIST SP 800-56A §5.8.1: for counter = 1 to `reps`, append
    /// hash(counter as 32-bit big-endian || Z || OtherInfo) to `out`.
    #[cfg_attr(
        hax,
        hax_lib::ensures(|_| {
            let finished = future(out);
            fstar!("$finished == Jwz.Kdf.Spec.rounds $hash $z $other_info (v $reps) $out")
        })
    )]
    pub(crate) fn rounds<D: Digest>(
        hash: &D,
        z: &[u8],
        other_info: &[u8],
        reps: u32,
        out: &mut Vec<u8>,
    ) {
        #[cfg(hax)]
        let initial = out.clone();
        for i in 0..reps {
            #[cfg(hax)]
            hax_lib::loop_invariant!(|i: u32| fstar!(
                "$out == Jwz.Kdf.Spec.rounds $hash $z $other_info (v $i) $initial"
            ));
            hash.append_digest([&be32(i + 1), z, other_info], out);
        }
    }
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

    /// A hash that records each input and answers with 32 bytes naming the round.
    struct Recording(core::cell::RefCell<Vec<Vec<u8>>>);

    impl Hash for Recording {
        fn algorithm(&self) -> HashAlgorithm {
            HashAlgorithm::Sha256
        }
        fn digest(&self, parts: &[&[u8]]) -> Vec<u8> {
            let input = parts.concat();
            let counter = input[3];
            self.0.borrow_mut().push(input);
            alloc::vec![counter; 32]
        }
    }

    /// NIST SP 800-56A §5.8.1 around the proven core (`kdf`, F*): for every key length
    /// up to three rounds and AlgorithmID, PartyUInfo and PartyVInfo of 0 to 2 bytes,
    /// round i hashes BE32(i) || Z || OtherInfo, there are ceil(len / 32) rounds, and
    /// the key is the rounds' outputs concatenated and truncated.
    #[test]
    fn sp_800_56a_5_8_1_layout_around_the_core() {
        let z = [0xa5, 0x5a, 0x01];
        for key_len in 1..=96usize {
            for (alg, apu, apv) in [
                (&b""[..], &b""[..], &b""[..]),
                (b"A", b"bc", b""),
                (b"xy", b"", b"z"),
            ] {
                let hash = Recording(core::cell::RefCell::new(Vec::new()));
                let key = concat_kdf(&hash, &z, alg, apu, apv, key_len).unwrap();
                let mut other_info = Vec::new();
                for datum in [alg, apu, apv] {
                    other_info
                        .extend_from_slice(&u32::try_from(datum.len()).unwrap().to_be_bytes());
                    other_info.extend_from_slice(datum);
                }
                other_info.extend_from_slice(&u32::try_from(key_len * 8).unwrap().to_be_bytes());
                let inputs = hash.0.borrow();
                assert_eq!(inputs.len(), key_len.div_ceil(32));
                for (i, input) in inputs.iter().enumerate() {
                    let mut expected = u32::try_from(i + 1).unwrap().to_be_bytes().to_vec();
                    expected.extend_from_slice(&z);
                    expected.extend_from_slice(&other_info);
                    assert_eq!(input, &expected, "key_len {key_len} round {i}");
                }
                assert_eq!(key.len(), key_len);
                for (i, byte) in key.iter().enumerate() {
                    assert_eq!(usize::from(*byte), i / 32 + 1);
                }
            }
        }
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
