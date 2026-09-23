//! The [`Loader`] trait every source and wrapper implements.

use super::artifact::{Artifact, Meta, TrustMaterial};
use super::cache::CacheError;
use super::transport::TransportError;

/// Validators for a conditional load.
#[derive(Clone, Copy, Debug, Default)]
pub struct Conditional<'a> {
    /// The `ETag` of the copy the caller holds.
    pub etag: Option<&'a str>,
    /// The `Last-Modified` of the copy the caller holds.
    pub last_modified: Option<&'a str>,
}

impl<'a> Conditional<'a> {
    /// No validators: always load a body.
    pub const NONE: Conditional<'static> = Conditional {
        etag: None,
        last_modified: None,
    };

    /// The validators of `meta`.
    pub fn from_meta(meta: &'a Meta) -> Self {
        Conditional {
            etag: meta.etag.as_deref(),
            last_modified: meta.last_modified.as_deref(),
        }
    }
}

/// A loaded body.
#[derive(Clone, Debug)]
pub struct Loaded {
    /// The bytes.
    pub body: Vec<u8>,
    /// Their metadata.
    pub meta: Meta,
    /// Set when the body is a fallback: the error that prevented a fresh load.
    pub stale: Option<LoadError>,
}

/// The result of a conditional load.
#[derive(Clone, Debug)]
pub enum Fetched {
    /// A body, new or served from a cache.
    Body(Loaded),
    /// The caller's copy is current.
    NotModified(Meta),
}

/// Why a load failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The cache store failed.
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// Offline mode and nothing cached for this artefact.
    #[error("offline and no cached {0}")]
    Offline(Artifact),
    /// A source answered "not modified" to a load without validators.
    #[error("unexpected not-modified for {0}")]
    UnexpectedNotModified(Artifact),
    /// A bundle could not be read or does not belong to this configuration.
    #[error("bundle: {0}")]
    Bundle(String),
    /// This loader cannot provide the artefact.
    #[error("{0} not available from this source")]
    Unavailable(Artifact),
}

/// A source of trust artefacts. Loaders are untrusted; see the [module docs](super).
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Loader {
    /// Loads `artifact`, or confirms the caller's copy if `cond` still matches.
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError>;

    /// The cache key under which [`CachingLoader`](super::CachingLoader) stores this
    /// loader's `artifact`. Defaults to a key for this loader's kind of source; loaders
    /// backed by a URL key by the URL.
    fn cache_key(&self, artifact: Artifact) -> String {
        artifact.cache_key("")
    }

    /// Loads `artifact` unconditionally.
    async fn load(&self, artifact: Artifact) -> Result<Loaded, LoadError> {
        match self.fetch(artifact, Conditional::NONE).await? {
            Fetched::Body(loaded) => Ok(loaded),
            Fetched::NotModified(_) => Err(LoadError::UnexpectedNotModified(artifact)),
        }
    }

    /// Loads both artefacts.
    async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
        let roots = self.load(Artifact::Roots).await?;
        let tsl = self.load(Artifact::Tsl).await?;
        Ok(TrustMaterial::new(
            roots.body, roots.meta, tsl.body, tsl.meta,
        ))
    }
}
