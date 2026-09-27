#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;
// clap's generated code refers to std; only the clap feature enables it.
#[cfg(feature = "std")]
extern crate std;

pub mod env;
pub mod time;

pub use env::{Env, EnvParseError, Tier};
pub use time::{Clock, Timestamp};
