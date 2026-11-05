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

//! [`FallbackLoader`]: a primary source with a backup.

use super::artifact::{Artifact, TrustMaterial};
use super::loader::{Fetched, LoadError, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use ti_cache::Conditional;

/// Tries `primary`; when it fails, loads from `backup` and records the primary's error
/// in [`Loaded::stale`](super::Loaded::stale).
#[derive(Debug)]
pub struct FallbackLoader<A, B> {
    primary: A,
    backup: B,
}

impl<A, B> FallbackLoader<A, B>
where
    A: Loader + MaybeSend + MaybeSync,
    B: Loader + MaybeSend + MaybeSync,
{
    /// `primary` with `backup` behind it.
    pub fn new(primary: A, backup: B) -> Self {
        FallbackLoader { primary, backup }
    }
}

impl<A, B> Loader for FallbackLoader<A, B>
where
    A: Loader + MaybeSend + MaybeSync,
    B: Loader + MaybeSend + MaybeSync,
{
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
        match self.primary.fetch(artifact, cond).await {
            Ok(fetched) => Ok(fetched),
            Err(primary_error) => match self.backup.fetch(artifact, cond).await? {
                Fetched::Body(mut loaded) => {
                    loaded.stale = Some(primary_error);
                    Ok(Fetched::Body(loaded))
                }
                not_modified @ Fetched::NotModified(_) => Ok(not_modified),
            },
        }
    }

    fn cache_key(&self, artifact: Artifact) -> String {
        self.primary.cache_key(artifact)
    }

    async fn revalidate(&self) -> Result<(), LoadError> {
        self.primary.revalidate().await
    }

    /// One source for the whole set: a list of the primary with a signature of the backup
    /// would not verify, while the backup's own set does.
    async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
        match self.primary.load_all().await {
            Ok(material) => Ok(material),
            Err(_) => self.backup.load_all().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;

    use super::*;
    use crate::load::{Meta, Source, StaticLoader, Timestamp, TrustMaterial};

    struct Failing;

    impl Loader for Failing {
        async fn fetch(
            &self,
            artifact: Artifact,
            _: Conditional<'_>,
        ) -> Result<Fetched, LoadError> {
            Err(LoadError::Offline(artifact))
        }
    }

    /// TSLDET-013: a primary with a list but no signature hands over the whole set.
    #[test]
    fn tsldet_013_the_backup_supplies_the_whole_set() {
        struct ListWithoutSignature;
        impl Loader for ListWithoutSignature {
            async fn fetch(
                &self,
                artifact: Artifact,
                _: Conditional<'_>,
            ) -> Result<Fetched, LoadError> {
                match artifact {
                    Artifact::TslSignature => Err(LoadError::Offline(artifact)),
                    _ => Ok(Fetched::Body(crate::load::Loaded {
                        body: b"primary".to_vec(),
                        meta: meta(),
                        stale: None,
                    })),
                }
            }
        }
        fn meta() -> Meta {
            Meta {
                etag: None,
                last_modified: None,
                fetched_at: Timestamp(1),
                max_age: None,
                source: Source::Bundle,
            }
        }
        let backup = StaticLoader::new(
            TrustMaterial::new(b"roots".to_vec(), meta(), b"backup".to_vec(), meta())
                .with_detached(Some(crate::load::Detached {
                    signature: b"sig".to_vec(),
                    signature_meta: meta(),
                    signer_status: None,
                })),
        );
        let material =
            block_on(FallbackLoader::new(ListWithoutSignature, backup).load_all()).unwrap();
        assert_eq!(material.tsl, b"backup");
    }

    #[test]
    fn backup_serves_and_records_the_primary_error() {
        let meta = Meta {
            etag: Some("b".into()),
            last_modified: None,
            fetched_at: Timestamp(1),
            max_age: None,
            source: Source::Bundle,
        };
        let backup = StaticLoader::new(TrustMaterial::new(
            b"roots".to_vec(),
            meta.clone(),
            b"tsl".to_vec(),
            meta,
        ));
        let loader = FallbackLoader::new(Failing, backup);
        let tsl = block_on(loader.load(Artifact::Tsl)).unwrap();
        assert_eq!(tsl.body, b"tsl");
        assert_eq!(tsl.stale, Some(LoadError::Offline(Artifact::Tsl)));
    }
}
