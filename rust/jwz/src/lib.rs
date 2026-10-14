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

//! JOSE for Rust: an open algorithm registry ([`jwa`]), pluggable cryptography
//! ([`crypto`]) and keys ([`keys`]), JWS, JWE, JWT claims and validation profiles
//! ([`profile`]).
//!
//! Start with the [`guide`]: verifying a JWT from a JWK Set, choosing a profile,
//! encrypting, keys in HSMs, further algorithms, the browser. Design decisions and their
//! reasons: `docs/adr/0001-jwz.md`.
#![no_std]
#![forbid(unsafe_code)]
// Input never panics the library (ADR 0001, auditability): tests may unwrap.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;
#[cfg(any(feature = "std", test, hax))]
extern crate std;

#[cfg(feature = "rsa")]
compile_error!("rsa: not yet implemented (jwz milestone 1 has the RSA key data model only)");

pub mod b64;
pub mod compact;
pub mod crypto;
mod error;
pub mod header;
mod json;
pub mod jwa;
#[cfg(feature = "jwe")]
pub mod jwe;
pub mod jwk;
#[cfg(feature = "jws")]
pub mod jws;
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod keys;
pub mod profile;
// Documentation only; compiled for rustdoc and its doctests, which need every format.
#[cfg(all(
    any(doc, doctest),
    feature = "std",
    feature = "jws",
    feature = "jwe",
    feature = "jwt",
    feature = "crypto-rustcrypto"
))]
#[doc = include_str!("../docs/guide.md")]
pub mod guide {}
#[cfg(kani)]
mod proofs;
pub mod x5c;

pub use error::{Error, ErrorCode};
