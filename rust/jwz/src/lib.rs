//! JOSE for Rust in the spirit of Go's `jwx`: an open algorithm registry ([`jwa`]),
//! pluggable cryptography ([`crypto`]) and, in later stages of milestone 1, keys, JWS,
//! JWE, JWT and validation profiles.
//!
//! Design decisions and their reasons: `docs/adr/0001-jwz.md`.
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
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "rsa")]
compile_error!("rsa: not yet implemented (jwz milestone 1 has the RSA key data model only)");

pub mod crypto;
pub mod jwa;
