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

//! Exclusive XML canonicalization and verification of the one XMLDSig/XAdES profile the
//! gematik TSL is signed with.
//!
//! The crate implements part A of `spec/tsl-xmldsig/README.md`: it parses strictly,
//! canonicalizes with Exclusive C14N 1.0, checks the enveloped signature against the
//! fixed profile and the digests of its two references. It verifies no signature value
//! and no certificate: it returns the canonical `SignedInfo`, the raw signature value and
//! the signer certificate, and the caller verifies those with its own algorithms
//! (`ti-pki` does, through `ti_pki::algorithms`).
//!
//! Everything outside the profile fails closed. Each [`Error`] names the specification
//! rule it enforces.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::arithmetic_side_effects
    )
)]

extern crate alloc;

mod c14n;
mod error;
mod parse;
#[cfg(kani)]
mod proofs;
mod verify;

pub use error::{Error, ErrorKind};
pub use parse::{Document, Limits};
pub use verify::SignedTsl;
