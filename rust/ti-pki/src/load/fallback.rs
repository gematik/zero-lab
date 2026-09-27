//! [`FallbackLoader`]: a primary source with a backup.

use super::artifact::Artifact;
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
