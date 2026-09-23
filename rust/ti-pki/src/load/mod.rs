//! Loading, caching and hot reload of trust material (roots.json and the TSL).
//!
//! Loaders are untrusted. Trust never comes from where bytes were obtained.
//! roots.json is verified by the cross-certificate walk against the embedded anchor,
//! the TSL by its signature against the embedded TSL-CA, regardless of whether the
//! bytes came from HTTP, a mounted file, an offline bundle or a cache. A misbehaving
//! loader can therefore only deny service or serve stale data, and staleness is caught
//! by the freshness policy.
//!
//! # Composition
//!
//! Loaders wrap each other; a typical production stack:
//!
//! ```text
//! Reloader ── tick() ──► FallbackLoader
//!                         ├─ primary: CachingLoader ── CacheStore (memory, Redis, …)
//!                         │            └─ HttpLoader ── Transport (reqwest, files, …)
//!                         └─ backup:  StaticLoader ◄── Bundle (offline CBOR file)
//! ```
//!
//! [`Reloader`] verifies whatever the stack returns and swaps both artefacts together;
//! request handlers read the result through [`TrustStoreHandle::snapshot`].
//!
//! The traits ([`Transport`], [`CacheStore`], [`Loader`], [`Clock`]) have no `Send`
//! bounds, so they can be implemented over single-threaded browser APIs; the loader
//! structs bound their parameters with [`MaybeSend`]/[`MaybeSync`] instead.
//!
//! # Failure handling
//!
//! | Condition | Store served | Status state | Readiness |
//! |---|---|---|---|
//! | load ok, changed | new | Fresh | ready |
//! | load ok, unchanged | current | Fresh | ready |
//! | load error, staleness < `stale_if_error` | current | Stale | ready |
//! | load error, < `hard_expiry` | current | Degraded | ready |
//! | load error, ≥ `hard_expiry` | none (`Err`) | Expired | not ready |
//! | verify error | current (never swapped) | as above by staleness | as above |
//!
//! The crate itself does not log. [`ReloadOutcome`] tells the caller what happened; a
//! verification failure ([`ReloadError::Verify`]) means possible tampering and deserves
//! an error-level log at once, a load failure a warning while `Stale` and an error from
//! `Degraded` on. The `tokio` feature's driver logs exactly that.

mod artifact;
mod cache;
mod caching;
mod clock;
mod fallback;
#[cfg(feature = "os")]
mod file;
mod http;
mod loader;
mod maybe_send;
mod reload;
mod static_;
mod transport;
mod verify;

pub use artifact::{
    Artifact, ArtifactRequest, ArtifactResponse, Meta, ResponseMeta, Source, TrustMaterial,
    content_etag,
};
pub use cache::{CacheEntry, CacheError, CachePolicy, CacheStore, MemoryCacheStore};
pub use caching::CachingLoader;
#[cfg(any(test, feature = "test-util"))]
pub use clock::FixedClock;
#[cfg(feature = "os")]
pub use clock::SystemClock;
pub use clock::{Clock, Timestamp};
pub use fallback::FallbackLoader;
#[cfg(feature = "os")]
pub use file::FileTransport;
pub use http::HttpLoader;
pub use loader::{Conditional, Fetched, LoadError, Loaded, Loader};
pub use maybe_send::{MaybeSend, MaybeSync};
pub use reload::{
    Expired, MAX_PROD_HARD_EXPIRY, ReloadError, ReloadOutcome, ReloadPolicy, ReloadStatus,
    Reloader, State, TrustStoreHandle,
};
pub use static_::{Bundle, StaticLoader};
#[cfg(any(test, feature = "test-util"))]
pub use transport::{MockRequest, MockTransport};
pub use transport::{Transport, TransportError, TransportErrorKind};
pub use verify::{Verified, VerifyError};
