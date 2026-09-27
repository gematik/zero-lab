//! The PKCS#12 key derivation (RFC 7292 Appendix B.2): the MAC key of every file and
//! the keys and IVs of the legacy PBEs. PBES2 uses PBKDF2 instead, through `pkcs5`.

use sha2::Digest;
use sha2::digest::block_api::BlockSizeUser;
use zeroize::Zeroizing;

/// What the derived bytes are for (RFC 7292 B.3).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Purpose {
    /// Key material for encryption or decryption.
    #[cfg_attr(not(feature = "legacy"), allow(dead_code))]
    Key = 1,
    /// An initialisation vector.
    #[cfg_attr(not(feature = "legacy"), allow(dead_code))]
    Iv = 2,
    /// A MAC key.
    Mac = 3,
}

/// The password as RFC 7292 B.1 feeds it to the KDF: UTF-16 big-endian with a
/// two-byte terminator. An empty password is the terminator alone, as OpenSSL writes
/// it.
pub(crate) fn bmp_password(password: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 * password.len() + 2));
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// `len` bytes for `purpose` from `password` (see [`bmp_password`]), `salt` and
/// `iterations`, with hash `D`.
pub(crate) fn derive<D: Digest + BlockSizeUser>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    purpose: Purpose,
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let v = D::block_size();
    let diversifier = vec![purpose as u8; v];
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(&repeat_to_blocks(salt, v));
    input.extend_from_slice(&repeat_to_blocks(password, v));

    let mut out = Zeroizing::new(Vec::with_capacity(len));
    loop {
        let mut hash = D::new()
            .chain_update(&diversifier)
            .chain_update(&*input)
            .finalize();
        for _ in 1..iterations.max(1) {
            hash = D::digest(&hash);
        }
        let take = (len - out.len()).min(hash.len());
        out.extend_from_slice(&hash[..take]);
        if out.len() == len {
            return out;
        }
        // I_j = (I_j + B + 1) mod 2^(8v) for every v-byte block of I, B = A repeated.
        let b = repeat_to_blocks(&hash, v);
        for block in input.chunks_mut(v) {
            let mut carry = 1u16;
            for (i, byte) in block.iter_mut().enumerate().rev() {
                let sum = u16::from(*byte) + u16::from(b[i]) + carry;
                *byte = sum.to_le_bytes()[0];
                carry = sum >> 8;
            }
        }
    }
}

/// `data` repeated to fill `v * ceil(len / v)` bytes; empty for empty `data`.
fn repeat_to_blocks(data: &[u8], v: usize) -> Zeroizing<Vec<u8>> {
    let len = data.len().div_ceil(v) * v;
    Zeroizing::new(data.iter().copied().cycle().take(len).collect())
}

#[cfg(test)]
mod tests {
    use sha1::Sha1;

    use super::*;

    #[test]
    fn passwords_are_utf16_be_with_a_terminator() {
        assert_eq!(*bmp_password("00"), [0, 0x30, 0, 0x30, 0, 0]);
        assert_eq!(*bmp_password(""), [0, 0]);
        assert_eq!(*bmp_password("ä"), [0, 0xe4, 0, 0]);
    }

    /// RFC 7292 has no test vectors; these are the ones Bouncy Castle's PKCS12 tests
    /// and other implementations share.
    #[test]
    fn derivation_matches_the_shared_vectors() {
        // password "smeg", salt 0A58CF64530D823F, 1 iteration, SHA-1.
        let password = bmp_password("smeg");
        let salt = [0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f];
        let key = derive::<Sha1>(&password, &salt, 1, Purpose::Key, 24);
        assert_eq!(
            hex(&key),
            "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"
        );
        let iv = derive::<Sha1>(&password, &salt, 1, Purpose::Iv, 8);
        assert_eq!(hex(&iv), "79993dfe048d3b76");
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }
}
