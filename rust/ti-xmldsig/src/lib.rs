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
