/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The response model of ti-pki's use cases: read-only projections of a certificate, a
//! TSL and an offline check as the front ends show them. [`Certificate`] is a certificate
//! as `ti pki inspect` shows it, [`Finding`] and [`CertSummary`] the findings of a TSL
//! verification, [`Tsl`] a verified TSL as one document for a web view, [`Check`] an
//! offline check.
//!
//! The types only map: no I/O, no validation, no clock of their own; whatever is judged
//! at an instant takes it from the caller. With the `serde` feature they serialize to the
//! JSON the `ti` CLI and its WebAssembly build publish, which their schemas
//! (`ti-cli/schemas`, `ti-wasm/schemas`) describe; the shape is declared here, the format
//! is the host's.

mod certificate;
mod check;
mod finding;
mod oid;
mod tsl;

#[cfg(feature = "load")]
use core::fmt::Write as _;

#[cfg(feature = "load")]
use sha2::{Digest, Sha256};

pub use certificate::{Admission, Certificate, Key, ProfileHint};
pub use check::{Check, Issue, ProfileUsed, TrustNode, TslState};
pub use finding::{CertSummary, Finding, rejection_code};
pub use oid::{Oid, TypeOid};
pub use tsl::{
    Chain, Counts, List, Pointer, PostalAddress, Provider, Root, Roots, Scheme, Service, Signature,
    Skipped, Tsl,
};

use crate::Timestamp;

/// The version of every JSON document; fields are only added within it.
pub const SCHEMA: u32 = 1;

/// `valid`, `expired` or `not_yet_valid` at `now`; both bounds are inside the period
/// (RFC 5280 §4.1.2.5: notBefore through notAfter, inclusive).
pub fn validity(cert: &crate::Certificate, now: Timestamp) -> &'static str {
    if now < cert.not_before() {
        "not_yet_valid"
    } else if now > cert.not_after() {
        "expired"
    } else {
        "valid"
    }
}

/// `bytes` as upper-case hex pairs separated by `:`, as OpenSSL prints serials and key
/// identifiers.
fn hex(bytes: &[u8]) -> String {
    let pairs: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    pairs.join(":")
}

/// The SHA-256 of `cert` as lower-case hex without separators: the key the TSL view files
/// certificates under, safe in URLs.
#[cfg(feature = "load")]
fn fingerprint(cert: &crate::Certificate) -> String {
    Sha256::digest(cert.der())
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// `supplied` or `embedded`.
#[cfg(feature = "load")]
fn roots_source(source: crate::offline::RootsSource) -> &'static str {
    match source {
        crate::offline::RootsSource::Supplied => "supplied",
        crate::offline::RootsSource::Embedded => "embedded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_upper_case_pairs_joined_by_colons() {
        assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0A:FF:00");
        assert_eq!(hex(&[]), "");
    }

    #[cfg(feature = "load")]
    #[test]
    fn sha256_and_fingerprint_are_the_same_digest_in_two_notations() {
        let cert = crate::cert::tests::fixture(crate::cert::tests::SMCB_EE);
        let sha256 = cert.fingerprint_sha256();
        assert_eq!(fingerprint(&cert), sha256.replace(':', "").to_lowercase());
        assert_eq!(fingerprint(&cert).len(), 64);
        assert_eq!(sha256.len(), 32 * 3 - 1);
    }
}
