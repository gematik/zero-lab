//! The JSON reports on TI certificates and TSLs that the `ti` CLI and its WebAssembly
//! build share: [`certificate::describe`] for a certificate as `ti pki inspect` shows it,
//! and the TSL findings in [`tsl`]. The CLI's JSON schemas describe them.
//!
//! No I/O and no clock: every function that judges validity takes the instant.

pub mod certificate;
pub mod oid;
pub mod tsl;

use sha2::{Digest, Sha256};
use ti_pki::{Certificate, Timestamp};

pub use certificate::{CertificateInfo, describe};
pub use oid::OidInfo;

/// The version of every JSON report; fields are only added within it.
pub const SCHEMA: u32 = 1;

/// `bytes` as upper-case hex pairs separated by `:`, as OpenSSL prints fingerprints.
pub fn hex(bytes: &[u8]) -> String {
    let pairs: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    pairs.join(":")
}

/// The SHA-256 of `der` in [`hex`].
pub fn sha256(der: &[u8]) -> String {
    hex(&Sha256::digest(der))
}

/// `der` as a PEM `CERTIFICATE` block, LF line endings.
///
/// # Panics
///
/// Never: base64 of bytes held in memory cannot fail.
pub fn pem(der: &[u8]) -> String {
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der)
        .expect("base64 of a certificate held in memory cannot fail")
}

/// `valid`, `expired` or `not_yet_valid` at `now`.
pub fn validity(cert: &Certificate, now: Timestamp) -> &'static str {
    if now < cert.not_before() {
        "not_yet_valid"
    } else if now > cert.not_after() {
        "expired"
    } else {
        "valid"
    }
}
