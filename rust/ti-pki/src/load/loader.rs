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
use ti_store::{CacheError, Conditional, Meta};

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

    /// Loads an artefact that may be missing: `None` if the source does not have it or
    /// cannot reach it, or has only a stale copy that may belong to another list
    /// (TSLDET-010). A fault of the cache is an error, not a missing file.
    async fn load_optional(&self, artifact: Artifact) -> Result<Option<Loaded>, LoadError> {
        match self.load(artifact).await {
            Ok(loaded) => Ok(loaded.stale.is_none().then_some(loaded)),
            Err(
                LoadError::Transport(_)
                | LoadError::Unavailable(_)
                | LoadError::Offline(_)
                | LoadError::UnexpectedNotModified(_),
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The list's detached signature and signer status, where the source has them. A
    /// signature that cannot be loaded leaves the list to its enveloped signature
    /// (TSLDET-013); a status that cannot be loaded leaves it unqueried (TSLDET-022).
    ///
    /// # Errors
    ///
    /// A fault of the cache store.
    async fn load_detached(&self) -> Result<Option<Detached>, LoadError> {
        let Some(signature) = self.load_optional(Artifact::TslSignature).await? else {
            return Ok(None);
        };
        let status = self.load_optional(Artifact::TslSignerStatus).await?;
        Ok(Some(Detached {
            signature: signature.body,
            signature_meta: signature.meta,
            signer_status: status.map(|status| (status.body, status.meta)),
        }))
    }

    /// Loads every artefact: roots.json, the TSL and its [detached files](Self::load_detached).
    async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
        let roots = self.load(Artifact::Roots).await?;
        let tsl = self.load(Artifact::Tsl).await?;
        let detached = self.load_detached().await?;
        Ok(TrustMaterial::new(roots.body, roots.meta, tsl.body, tsl.meta).with_detached(detached))
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;
    use ti_store::{Meta, Source};

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

    /// A broken cache is a fault, not "no signature published": swallowing it hid that
    /// the CLI never reached the detached path.
    #[test]
    fn tsldet_013_a_cache_fault_is_not_taken_for_a_missing_signature() {
        let stub = Stub {
            detached: || {
                Err(LoadError::Cache(CacheError {
                    message: "no namespace".into(),
                }))
            },
        };
        assert!(matches!(
            block_on(stub.load_all()),
            Err(LoadError::Cache(_))
        ));
    }

    #[test]
    fn tsldet_013_an_unavailable_signature_leaves_the_enveloped_path() {
        let stub = Stub {
            detached: || Err(LoadError::Unavailable(Artifact::TslSignature)),
        };
        assert!(block_on(stub.load_all()).unwrap().detached.is_none());
    }

    /// A fallback or stale copy may belong to another list: not part of this set.
    #[test]
    fn tsldet_010_stale_detached_files_are_absent() {
        let stub = Stub {
            detached: || Ok(loaded(Some(LoadError::Offline(Artifact::TslSignature)))),
        };
        assert!(block_on(stub.load_all()).unwrap().detached.is_none());
    }
}
