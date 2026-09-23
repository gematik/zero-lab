//! [`HttpLoader`]: turns a [`TrustConfig`]'s URLs into transport requests.

use std::borrow::Cow;

use super::artifact::{Artifact, ArtifactRequest, ArtifactResponse};
use super::clock::Clock;
use super::loader::{Conditional, Fetched, LoadError, Loaded, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use super::transport::Transport;
use crate::TrustConfig;

/// Loads the artefacts from the URLs in a [`TrustConfig`] through any [`Transport`],
/// HTTP or not ([`FileTransport`](super::FileTransport) ignores the URL). No caching and
/// no retries: those belong to [`CachingLoader`](super::CachingLoader) and the transport.
#[derive(Debug)]
pub struct HttpLoader<T, C> {
    roots_url: Cow<'static, str>,
    tsl_url: Cow<'static, str>,
    transport: T,
    clock: C,
}

impl<T: Transport + MaybeSend + MaybeSync, C: Clock + MaybeSend + MaybeSync> HttpLoader<T, C> {
    /// A loader for `config`'s URLs.
    pub fn new(config: &TrustConfig, transport: T, clock: C) -> Self {
        HttpLoader {
            roots_url: config.roots_url.clone(),
            tsl_url: config.tsl_url.clone(),
            transport,
            clock,
        }
    }

    fn url(&self, artifact: Artifact) -> &str {
        match artifact {
            Artifact::Roots => &self.roots_url,
            Artifact::Tsl => &self.tsl_url,
        }
    }
}

impl<T: Transport + MaybeSend + MaybeSync, C: Clock + MaybeSend + MaybeSync> Loader
    for HttpLoader<T, C>
{
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
        let request = ArtifactRequest {
            artifact,
            url: self.url(artifact),
            etag: cond.etag,
            last_modified: cond.last_modified,
        };
        let response = self.transport.get(&request).await?;
        let now = self.clock.now();
        Ok(match response {
            ArtifactResponse::Fresh { body, meta } => Fetched::Body(Loaded {
                body,
                meta: meta.at(now),
                stale: None,
            }),
            ArtifactResponse::NotModified { meta } => Fetched::NotModified(meta.at(now)),
        })
    }

    fn cache_key(&self, artifact: Artifact) -> String {
        artifact.cache_key(self.url(artifact))
    }
}
