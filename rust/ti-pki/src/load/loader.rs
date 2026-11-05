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

//! The [`Loader`] trait every source and wrapper implements.

use super::artifact::{Artifact, Detached, TrustMaterial};
use super::transport::TransportError;
use ti_cache::{CacheError, Conditional, Meta};

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

    /// The list's detached files. The signature is required: without it no list verifies
    /// (TSLDET-013). The status is optional, and a copy that is only a stale fallback is
    /// not used; its absence leaves the status unqueried (TSLDET-022).
    ///
    /// # Errors
    ///
    /// Why the signature could not be loaded, or a fault of the cache store.
    async fn load_detached(&self) -> Result<Detached, LoadError> {
        let signature = self.load(Artifact::TslSignature).await?;
        let status = match self.load(Artifact::TslSignerStatus).await {
            Ok(status) => status.stale.is_none().then_some(status),
            Err(
                LoadError::Transport(_)
                | LoadError::Unavailable(_)
                | LoadError::Offline(_)
                | LoadError::UnexpectedNotModified(_),
            ) => None,
            Err(error) => return Err(error),
        };
        Ok(Detached {
            signature: signature.body,
            signature_meta: signature.meta,
            signer_status: status.map(|status| (status.body, status.meta)),
        })
    }

    /// Makes the next load ask the origin for the list and its detached files again:
    /// after a signature that does not fit, a cached set must not go on failing until it
    /// ages out (TSLDET-013). Sources without a cache have nothing to do.
    ///
    /// # Errors
    ///
    /// A fault of the cache store.
    async fn revalidate(&self) -> Result<(), LoadError> {
        Ok(())
    }

    /// Loads every artefact: roots.json, the TSL and its [detached files](Self::load_detached).
    async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
        let roots = self.load(Artifact::Roots).await?;
        let tsl = self.load(Artifact::Tsl).await?;
        let detached = self.load_detached().await?;
        Ok(
            TrustMaterial::new(roots.body, roots.meta, tsl.body, tsl.meta)
                .with_detached(Some(detached)),
        )
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;
    use ti_cache::{Meta, Source};

    use super::*;
    use crate::time::Timestamp;

    /// Answers the two required artefacts, and the detached ones as `detached` says.
    struct Stub {
        detached: fn() -> Result<Loaded, LoadError>,
    }

    fn loaded(stale: Option<LoadError>) -> Loaded {
        Loaded {
            body: b"body".to_vec(),
            meta: Meta {
                etag: None,
                last_modified: None,
                fetched_at: Timestamp(1),
                max_age: None,
                source: Source::Http,
            },
            stale,
        }
    }

    impl Loader for Stub {
        async fn fetch(
            &self,
            artifact: Artifact,
            _: Conditional<'_>,
        ) -> Result<Fetched, LoadError> {
            match artifact {
                Artifact::TslSignature | Artifact::TslSignerStatus => {
                    (self.detached)().map(Fetched::Body)
                }
                _ => Ok(Fetched::Body(loaded(None))),
            }
        }
    }

    /// A broken cache is a fault, and without a signature there is no material.
    #[test]
    fn tsldet_013_a_missing_signature_fails_the_load() {
        let cache_fault = Stub {
            detached: || {
                Err(LoadError::Cache(CacheError {
                    message: "no namespace".into(),
                }))
            },
        };
        assert!(matches!(
            block_on(cache_fault.load_all()),
            Err(LoadError::Cache(_))
        ));
        let unavailable = Stub {
            detached: || Err(LoadError::Unavailable(Artifact::TslSignature)),
        };
        assert!(matches!(
            block_on(unavailable.load_all()),
            Err(LoadError::Unavailable(Artifact::TslSignature))
        ));
    }

    /// A stale status may be about another moment; it is not part of this set.
    #[test]
    fn tsldet_022_a_stale_status_is_absent() {
        struct StaleStatus;
        impl Loader for StaleStatus {
            async fn fetch(
                &self,
                artifact: Artifact,
                _: Conditional<'_>,
            ) -> Result<Fetched, LoadError> {
                Ok(Fetched::Body(loaded(
                    (artifact == Artifact::TslSignerStatus).then_some(LoadError::Offline(artifact)),
                )))
            }
        }
        let material = block_on(StaleStatus.load_all()).unwrap();
        assert!(material.detached.unwrap().signer_status.is_none());
    }
}
