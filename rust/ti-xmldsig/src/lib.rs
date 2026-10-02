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

mod error;
mod parse;

pub use error::{Error, ErrorKind};
pub use parse::{Document, Limits};
