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
/// hash (TSLSIG-050, A_30044 (2) of C_12791). Without a readable hash the TSL is fetched
/// as before.
///
/// The list, its `.sig` and its `.ocsp` come from [`TrustConfig::tsl_detached_url`] as one
/// set (`spec/tsl-detached` TSLDET-010), under a hash read from the HTTPS point. Without a
/// readable hash the list comes from HTTPS itself, never from the plain-HTTP origin.
#[derive(Debug)]
pub struct HttpLoader<T, C> {
    roots_url: Cow<'static, str>,
    tsl_url: Cow<'static, str>,
    tsl_detached_url: Cow<'static, str>,
    transport: T,
    clock: C,
}

impl<T: Transport + MaybeSend + MaybeSync, C: Clock + MaybeSend + MaybeSync> HttpLoader<T, C> {
    /// A loader for `config`'s URLs.
    pub fn new(config: &TrustConfig, transport: T, clock: C) -> Self {
        HttpLoader {
            roots_url: config.roots_url.clone(),
            tsl_url: config.tsl_url.clone(),
            tsl_detached_url: config.tsl_detached_url.clone(),
            transport,
            clock,
        }
    }

    /// Where `artifact` is fetched from. The list's own URL is the HTTPS point: the
    /// plain-HTTP origin is asked for it only under a hash from HTTPS, in
    /// [`fetch_tsl_by_hash`](Self::fetch_tsl_by_hash).
    fn url(&self, artifact: Artifact) -> Option<Cow<'_, str>> {
        let detached = |suffix: &str| {
            self.tsl_detached_url
                .strip_suffix(".xml")
                .map(|stem| Cow::Owned(format!("{stem}{suffix}")))
        };
        match artifact {
            Artifact::Roots => Some(Cow::Borrowed(self.roots_url.as_ref())),
            Artifact::Tsl => Some(Cow::Borrowed(self.tsl_url.as_ref())),
            Artifact::TslSignature => detached(".sig"),
            Artifact::TslSignerStatus => detached(".ocsp"),
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
        // TSLDET-014: the list comes from where its signature is (A_21177): HTTPS may
        // already have a list whose `.sig` is not published yet (A_21178 allows an hour),
        // and taking it would replace the set in hand with one that cannot verify. So a
        // list that does not match, or no list, is a failure to retry, with the set in hand
        // kept. The origin is plain HTTP: no validators go there and its "not modified" is not
        // believed, or an unauthenticated answer would renew the list's age.
        let origin = self.tsl_detached_url.as_ref();
        let unusable = |why: String| {
            LoadError::Transport(TransportError {
                kind: TransportErrorKind::Other,
                message: format!("the TSL at {origin}: {why}"),
                retryable: true,
            })
        };
        let response = self
            .transport
            .get(&ArtifactRequest {
                artifact: Artifact::Tsl,
                url: origin,
                etag: None,
                last_modified: None,
            })
            .await
            .map_err(|e| unusable(e.message))?;
        let ArtifactResponse::Fresh { body, meta } = response else {
            return Err(unusable(
                "answered \"not modified\" to no validators".to_owned(),
            ));
        };
        let actual = content_etag(&body);
        if actual != published {
            return Err(unusable(format!(
                "does not match its published SHA-256 ({actual}, published {published}); a \
                 new list may be under way, its signature is not published yet"
            )));
        }
        Ok(Fetched::Body(checked_list(body, meta, published, now)))
    }
}

/// A list that matched the published hash, with the hash as its entity tag.
fn checked_list(
    body: Vec<u8>,
    mut meta: ResponseMeta,
    published: String,
    now: crate::time::Timestamp,
) -> Loaded {
    meta.etag = Some(published);
    Loaded {
        body,
        meta: meta.at(now),
        stale: None,
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
        let url = self.url(artifact).ok_or(LoadError::Unavailable(artifact))?;
        let request = ArtifactRequest {
            artifact,
            url: &url,
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
        artifact.cache_key(self.url(artifact).as_deref().unwrap_or(""))
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;

    use super::*;
    use crate::load::{MockTransport, TrustMaterial, content_etag};
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

    const DETACHED: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref."
    );

    fn ref_set() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let read = |suffix: &str| std::fs::read(format!("{DETACHED}{suffix}")).unwrap();
        (read("xml"), read("sig"), read("ocsp"))
    }

    fn load_all_ref(
        config: &TrustConfig,
        transport: &MockTransport,
    ) -> Result<TrustMaterial, LoadError> {
        let clock = FixedClock::new(Timestamp(1_767_225_600));
        let loader = HttpLoader::new(config, transport, &clock);
        block_on(loader.load_all())
    }

    fn transport_error() -> TransportError {
        TransportError {
            kind: TransportErrorKind::Other,
            message: "blocked".into(),
            retryable: true,
        }
    }

    /// TSLDET-010: blocking the hash must not leave the list to the unauthenticated
    /// origin; it then comes from the HTTPS point, with the caller's validators.
    #[test]
    fn tsldet_010_unreadable_hash_takes_the_list_from_https() {
        let transport = MockTransport::new([
            Err(transport_error()),
            Ok(fresh(TSL, Some("\"e\""), Source::Http)),
        ]);
        let Fetched::Body(loaded) = fetch(&transport, Some("\"old\"")).unwrap() else {
            panic!("a body");
        };
        assert_eq!(loaded.body, TSL);
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].url, crate::tsl::URL_PROD);
        assert_eq!(requests[1].etag.as_deref(), Some("\"old\""));
    }

    /// TSLDET-010: the plain-HTTP origin gets no validators, and its "not modified" is
    /// not believed: it would renew the list's age without any authentication.
    #[test]
    fn tsldet_010_a_not_modified_from_the_plain_origin_is_not_believed() {
        let transport = MockTransport::new([
            Ok(fresh(hash_of(TSL).as_bytes(), None, Source::Http)),
            Ok(ArtifactResponse::NotModified {
                meta: ResponseMeta {
                    etag: None,
                    last_modified: None,
                    max_age: None,
                    source: Source::Http,
                },
            }),
        ]);
        let Err(LoadError::Transport(error)) = fetch(&transport, Some("sha256:older")) else {
            panic!("no list, and no confirmation of the old one");
        };
        assert!(error.retryable);
        let requests = transport.requests();
        assert_eq!(requests[1].url, crate::tsl::URL_DETACHED_PROD);
        assert_eq!(requests[1].etag, None);
    }

    /// TSLDET-014: the plain-HTTP origin blocked, or lagging behind the published hash:
    /// its signature would not fit the list HTTPS has, so nothing replaces the set in hand
    /// and the failure is one to retry. HTTPS is not asked.
    #[test]
    fn tsldet_014_an_unusable_plain_origin_is_a_retryable_failure() {
        for origin in [
            Err(transport_error()),
            Ok(fresh(b"older", None, Source::Http)),
        ] {
            let transport = MockTransport::new([
                Ok(fresh(hash_of(TSL).as_bytes(), None, Source::Http)),
                origin,
            ]);
            let Err(LoadError::Transport(error)) = fetch(&transport, None) else {
                panic!("a retryable failure");
            };
            assert!(error.retryable);
            assert_eq!(
                transport.requests().len(),
                2,
                "HTTPS is not asked for the list"
            );
        }
    }

    /// TSLDET-010, 012: the hash from the HTTPS point, the set from the automated one.
    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_010_http_loader_fetches_the_set_from_the_detached_origin() {
        let (xml, sig, ocsp) = ref_set();
        let config = TrustConfig::preset(crate::Env::Ref);
        let transport = MockTransport::new([
            Ok(fresh(b"{}", None, Source::Http)),
            Ok(fresh(hash_of(&xml).as_bytes(), None, Source::Http)),
            Ok(fresh(&xml, None, Source::Http)),
            Ok(fresh(&sig, None, Source::Http)),
            Ok(fresh(&ocsp, None, Source::Http)),
        ]);
        let material = load_all_ref(&config, &transport).unwrap();
        let detached = material
            .detached
            .as_ref()
            .expect("the signature was loaded");
        assert_eq!(detached.signature, sig);
        assert_eq!(
            detached.signer_status.as_ref().map(|(b, _)| b.as_slice()),
            Some(ocsp.as_slice())
        );
        assert_eq!(material.tsl, xml);
        let urls: Vec<String> = transport.requests().into_iter().map(|r| r.url).collect();
        assert_eq!(
            urls,
            [
                crate::roots::URL_REF.to_owned(),
                "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.sha2".to_owned(),
                crate::tsl::URL_DETACHED_REF.to_owned(),
                "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.sig"
                    .to_owned(),
                "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.ocsp"
                    .to_owned(),
            ]
        );
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_010_list_not_matching_published_hash_is_retryable() {
        let (xml, _, _) = ref_set();
        let config = TrustConfig::preset(crate::Env::Ref);
        let transport = MockTransport::new([
            Ok(fresh(b"{}", None, Source::Http)),
            Ok(fresh(
                hash_of(b"another list").as_bytes(),
                None,
                Source::Http,
            )),
            Ok(fresh(&xml, None, Source::Http)),
            Ok(fresh(&xml, None, Source::Http)),
        ]);
        let LoadError::Transport(error) = load_all_ref(&config, &transport).unwrap_err() else {
            panic!("a hash mismatch is a transport error");
        };
        assert!(error.retryable);
    }

    /// TSLDET-013: with the signature's download failing there is no material; nothing
    /// falls back to an unsigned list.
    #[test]
    fn tsldet_013_no_signature_no_material() {
        let transport = MockTransport::new([
            Ok(fresh(b"{}", None, Source::Http)),
            Ok(fresh(hash_of(TSL).as_bytes(), None, Source::Http)),
            Ok(fresh(TSL, None, Source::Http)),
            Err(transport_error()),
        ]);
        assert!(matches!(
            load_all_ref(&TrustConfig::preset_prod(), &transport),
            Err(LoadError::Transport(_))
        ));
    }

    /// TSLDET-012: the `.sig` and `.ocsp` URIs of A_21182 are the list's, by suffix.
    #[test]
    fn tsldet_012_the_detached_uris_follow_the_list() {
        let transport = MockTransport::new([]);
        let clock = FixedClock::new(Timestamp(1_767_225_600));
        let loader = HttpLoader::new(&TrustConfig::preset_prod(), &transport, &clock);
        let origin = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL";
        assert_eq!(
            loader.url(Artifact::TslSignature).as_deref(),
            Some(format!("{origin}.sig").as_str())
        );
        assert_eq!(
            loader.url(Artifact::TslSignerStatus).as_deref(),
            Some(format!("{origin}.ocsp").as_str())
        );
    }

    /// A_30044 (2): the published hash decides whether the TSL is downloaded.
    #[test]
    fn tslsig_050_the_published_hash_decides_the_download() {
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
