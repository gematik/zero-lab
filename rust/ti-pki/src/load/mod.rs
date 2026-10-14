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

//! Loading, caching and hot reload of trust material (roots.json and the TSL).
//!
//! Loaders are untrusted. Trust never comes from where bytes were obtained.
//! roots.json is verified by the cross-certificate walk against the embedded anchor,
//! regardless of whether the bytes came from HTTP, a mounted file, an offline bundle or
//! a cache. The TSL is verified against the configured TSL signer CA, its `NextUpdate` and
//! the list before it, and online its signer's OCSP status ([`crate::tsl_signature`]);
//! of its CAs only those a verified root signed are kept ([`crate::tsl`]). A
//! misbehaving loader can therefore only deny service (withhold roots or CAs) or serve
//! stale data, and staleness is caught by the freshness policy.
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
//! The caching layer is [`ti_cache`], re-exported here: [`CachingLoader`] applies its
//! [`Cache`] to a [`Loader`], and other crates cache their own artefacts with the same
//! [`CacheStore`] and [`CachePolicy`].
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
mod caching;
mod fallback;
#[cfg(feature = "os")]
mod file;
mod http;
mod loader;
mod maybe_send;
mod reload;
mod static_;
mod transport;
pub(crate) mod verify;

#[cfg(any(test, feature = "test-util"))]
pub use crate::time::FixedClock;
#[cfg(all(
    feature = "os",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
pub use crate::time::SystemClock;
pub use crate::time::{Clock, Timestamp};
pub use artifact::{
    Artifact, ArtifactRequest, ArtifactResponse, ResponseMeta, TrustMaterial, content_etag,
};
pub use caching::CachingLoader;
pub use fallback::FallbackLoader;
#[cfg(feature = "os")]
pub use file::FileTransport;
pub use http::HttpLoader;
pub use loader::{Fetched, LoadError, Loaded, Loader};
pub use maybe_send::{MaybeSend, MaybeSync};
pub use reload::{
    Expired, MAX_PROD_HARD_EXPIRY, MAX_RELOAD_INTERVAL, ReloadError, ReloadOutcome, ReloadPolicy,
    ReloadStatus, Reloader, State, TrustStoreHandle,
};
pub use static_::{Bundle, StaticLoader};
pub use ti_cache::{
    Cache, CacheEntry, CacheError, CacheLookupError, CachePolicy, CacheStore, Cached, Conditional,
    MemoryCacheStore, Meta, Source,
};
#[cfg(any(test, feature = "test-util"))]
pub use transport::{MockRequest, MockTransport};
pub use transport::{PostRequest, Transport, TransportError, TransportErrorKind};
pub use verify::{Verified, VerifyError};
