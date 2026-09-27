//! The password integrity mode (RFC 7292 §5.1): an HMAC over the auth-safe octets with
//! a key from the PKCS#12 KDF.

use der::asn1::ObjectIdentifier;
use hmac::{KeyInit, Mac, SimpleHmac};
use sha1::Sha1;
use sha2::digest::block_api::BlockSizeUser;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::asn1::MacData;
use crate::kdf::{self, Purpose};
use crate::{Error, oids};

/// Checks `mac_data` over `content` with the KDF-ready `password`.
pub(crate) fn verify(mac_data: &MacData, password: &[u8], content: &[u8]) -> Result<(), Error> {
    let oid = mac_data.mac.algorithm.oid;
    let check = match oid {
        oids::SHA1 => check::<Sha1>,
        oids::SHA224 => check::<Sha224>,
        oids::SHA256 => check::<Sha256>,
        oids::SHA384 => check::<Sha384>,
        oids::SHA512 => check::<Sha512>,
        _ => return Err(Error::UnsupportedAlgorithm(oid)),
    };
    if check(
        password,
        mac_data.mac_salt.as_bytes(),
        mac_data.iterations,
        content,
        mac_data.mac.digest.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(Error::MacMismatch)
    }
}

/// The digest name of a MAC algorithm, for display.
pub(crate) fn name(oid: ObjectIdentifier) -> Option<&'static str> {
    Some(match oid {
        oids::SHA1 => "SHA-1",
        oids::SHA224 => "SHA-224",
        oids::SHA256 => "SHA-256",
        oids::SHA384 => "SHA-384",
        oids::SHA512 => "SHA-512",
        _ => return None,
    })
}

fn check<D: Digest + BlockSizeUser + Clone>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    content: &[u8],
    expected: &[u8],
) -> bool {
    // The MAC key is as long as the digest (RFC 7292 B.4).
    let key = kdf::derive::<D>(
        password,
        salt,
        iterations,
        Purpose::Mac,
        <D as Digest>::output_size(),
    );
    let Ok(mut mac) = <SimpleHmac<D> as KeyInit>::new_from_slice(&key) else {
        return false;
    };
    mac.update(content);
    mac.verify_slice(expected).is_ok()
}
