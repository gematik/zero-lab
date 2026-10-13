/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
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
