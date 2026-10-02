//! [`HttpLoader`]: turns a [`TrustConfig`]'s URLs into transport requests.

use std::borrow::Cow;

use super::artifact::{Artifact, ArtifactRequest, ArtifactResponse, ResponseMeta, content_etag};
use super::loader::{Fetched, LoadError, Loaded, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use super::transport::{Transport, TransportError, TransportErrorKind};
use crate::TrustConfig;
use crate::time::Clock;
use ti_cache::{Conditional, Source};

/// Loads the artefacts from the URLs in a [`TrustConfig`] through any [`Transport`],
/// HTTP or not ([`FileTransport`](super::FileTransport) ignores the URL). No caching and
/// no retries: those belong to [`CachingLoader`](super::CachingLoader) and the transport.
///
/// Over HTTP, the TSL is compared by the SHA-256 published next to it (`.sha2` for
/// `.xml`) before it is downloaded: a caller holding the list with that hash
/// (`sha256:<hex>` as its entity tag) gets "not modified", and a download must match the
/// hash (A_30044 (2) of C_12791). Without a readable hash the TSL is fetched as before.
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

    /// The SHA-256 published next to the TSL, in lowercase hex, if an HTTP source has
    /// one. A file source answers with the list itself, which is not a hash.
    async fn published_tsl_hash(&self) -> Option<String> {
        let url = format!("{}.sha2", self.tsl_url.strip_suffix(".xml")?);
        let response = self
            .transport
            .get(&ArtifactRequest {
                artifact: Artifact::Tsl,
                url: &url,
                etag: None,
                last_modified: None,
            })
            .await
            .ok()?;
        let ArtifactResponse::Fresh { body, meta } = response else {
            return None;
        };
        if meta.source != Source::Http {
            return None;
        }
        let hash = core::str::from_utf8(&body)
            .ok()?
            .split_whitespace()
            .next()?;
        (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    }

    async fn fetch_tsl_by_hash(
        &self,
        hash: &str,
        cond: Conditional<'_>,
    ) -> Result<Fetched, LoadError> {
        let published = format!("sha256:{hash}");
        let now = self.clock.now();
        if cond.etag == Some(published.as_str()) {
            return Ok(Fetched::NotModified(
                ResponseMeta {
                    etag: Some(published),
                    last_modified: None,
                    max_age: None,
                    source: Source::Http,
                }
                .at(now),
            ));
        }
        let response = self
            .transport
            .get(&ArtifactRequest {
                artifact: Artifact::Tsl,
                url: &self.tsl_url,
                etag: None,
                last_modified: None,
            })
            .await?;
        Ok(match response {
            ArtifactResponse::Fresh { body, mut meta } => {
                let actual = content_etag(&body);
                if actual != published {
                    return Err(LoadError::Transport(TransportError {
                        kind: TransportErrorKind::Other,
                        message: format!(
                            "the TSL does not match its published SHA-256 ({actual}, published \
                             {published}); a new list may be under way"
                        ),
                        retryable: true,
                    }));
                }
                meta.etag = Some(actual);
                Fetched::Body(Loaded {
                    body,
                    meta: meta.at(now),
                    stale: None,
                })
            }
            ArtifactResponse::NotModified { meta } => Fetched::NotModified(meta.at(now)),
        })
    }
}

impl<T: Transport + MaybeSend + MaybeSync, C: Clock + MaybeSend + MaybeSync> Loader
    for HttpLoader<T, C>
{
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
        if artifact == Artifact::Tsl
            && let Some(hash) = self.published_tsl_hash().await
        {
            return self.fetch_tsl_by_hash(&hash, cond).await;
        }
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

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;

    use super::*;
    use crate::load::{MockTransport, content_etag};
    use crate::time::{FixedClock, Timestamp};

    const TSL: &[u8] = b"<TrustServiceStatusList/>";

    fn fresh(body: &[u8], etag: Option<&str>, source: Source) -> ArtifactResponse {
        ArtifactResponse::Fresh {
            body: body.to_vec(),
            meta: ResponseMeta {
                etag: etag.map(Into::into),
                last_modified: None,
                max_age: None,
                source,
            },
        }
    }

    fn hash_of(body: &[u8]) -> String {
        content_etag(body).trim_start_matches("sha256:").to_owned()
    }

    fn fetch(transport: &MockTransport, etag: Option<&str>) -> Result<Fetched, LoadError> {
        let clock = FixedClock::new(Timestamp(1_767_225_600));
        let loader = HttpLoader::new(&TrustConfig::preset_prod(), transport, &clock);
        block_on(loader.fetch(
            Artifact::Tsl,
            Conditional {
                etag,
                last_modified: None,
            },
        ))
    }

    /// A_30044 (2): the published hash decides whether the TSL is downloaded.
    #[test]
    fn the_published_hash_decides_the_download() {
        let sha2 = format!("{}  ECC-RSA_TSL.xml\n", hash_of(TSL).to_uppercase());
        let transport = MockTransport::new([Ok(fresh(sha2.as_bytes(), None, Source::Http))]);
        let held = content_etag(TSL);
        let Fetched::NotModified(meta) = fetch(&transport, Some(&held)).unwrap() else {
            panic!("the held TSL has the published hash");
        };
        assert_eq!(meta.etag.as_deref(), Some(held.as_str()));
        let requests = transport.requests();
        assert_eq!(requests.len(), 1, "only the hash was fetched");
        assert_eq!(
            requests[0].url,
            "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.sha2"
        );

        let transport = MockTransport::new([
            Ok(fresh(hash_of(TSL).as_bytes(), None, Source::Http)),
            Ok(fresh(TSL, Some("\"http-etag\""), Source::Http)),
        ]);
        let Fetched::Body(loaded) = fetch(&transport, Some("sha256:older")).unwrap() else {
            panic!("a new hash means a download");
        };
        assert_eq!(loaded.body, TSL);
        assert_eq!(
            loaded.meta.etag.as_deref(),
            Some(held.as_str()),
            "keyed by content"
        );
        assert_eq!(transport.requests()[1].etag, None);
    }

    #[test]
    fn a_download_must_match_the_published_hash() {
        let transport = MockTransport::new([
            Ok(fresh(
                hash_of(b"another list").as_bytes(),
                None,
                Source::Http,
            )),
            Ok(fresh(TSL, None, Source::Http)),
        ]);
        let error = fetch(&transport, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match its published SHA-256"),
            "{error}"
        );
    }

    /// No readable hash, or one from a file source: the TSL is fetched as before.
    #[test]
    fn without_a_hash_the_tsl_is_fetched_as_before() {
        for first in [
            Ok(fresh(b"not a hash", None, Source::Http)),
            Ok(fresh(TSL, None, Source::File)),
            Err(TransportError {
                kind: TransportErrorKind::Status(404),
                message: "not found".into(),
                retryable: false,
            }),
        ] {
            let transport =
                MockTransport::new([first, Ok(fresh(TSL, Some("\"e1\""), Source::Http))]);
            let Fetched::Body(loaded) = fetch(&transport, Some("\"e0\"")).unwrap() else {
                panic!("fetched");
            };
            assert_eq!(loaded.meta.etag.as_deref(), Some("\"e1\""));
            assert_eq!(transport.requests()[1].etag.as_deref(), Some("\"e0\""));
        }
    }
}
