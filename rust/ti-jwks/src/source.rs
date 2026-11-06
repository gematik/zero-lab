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

//! [`JwksSource`]: one `jwks_uri`, its cache and the transport to it.

use core::time::Duration;

use jwz::jwk::{Jwk, JwkSet, KeyPurpose};
use ti_cache::{
    Cache, CacheControl, CacheEntry, CacheLookupError, CachePolicy, CacheStore, Conditional,
    FreshnessBounds, Meta, OriginResponse, Source,
};
use ti_types::Clock;

use crate::error::Error;
use crate::http::{Request, Response, Transport};

/// How large a set may be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of the body; 64 KiB by default, room for a hundred keys with certificates.
    pub max_body: u64,
    /// Keys in the set; 100 by default.
    pub max_keys: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_body: 64 * 1024,
            max_keys: 100,
        }
    }
}

/// The cache policy the crate's rules ask for: the origin's lifetime within 5 minutes and
/// 24 hours, one hour without one, not served past it when the origin fails, a forced
/// refresh at most once a minute.
pub fn policy() -> CachePolicy {
    CachePolicy {
        max_age: Duration::from_hours(1),
        stale_if_error: Duration::ZERO,
        offline: false,
        origin_freshness: Some(FreshnessBounds {
            min: Duration::from_mins(5),
            max: Duration::from_hours(24),
        }),
        min_forced_interval: Duration::from_mins(1),
    }
}

/// The keys at one `jwks_uri`.
#[derive(Debug)]
pub struct JwksSource<S, C, T> {
    url: String,
    key: String,
    cache: Cache<S, C>,
    transport: T,
    limits: Limits,
}

impl<S: CacheStore, C: Clock, T: Transport> JwksSource<S, C, T> {
    /// The set at `url`, kept in `cache` (built with [`policy`] or a policy of the
    /// caller's) and fetched through `transport`.
    ///
    /// # Errors
    ///
    /// [`Error::NotHttps`] for a URL that is not `https`.
    pub fn new(url: &str, cache: Cache<S, C>, transport: T) -> Result<Self, Error> {
        let https = url
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
        if !https || url.len() == 8 {
            return Err(Error::NotHttps(url.to_owned()));
        }
        Ok(JwksSource {
            url: url.to_owned(),
            key: format!("ti-jwks/v1/{url}"),
            cache,
            transport,
            limits: Limits::default(),
        })
    }

    /// This source with other limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The current set: the stored one while fresh, else what the origin answers.
    ///
    /// # Errors
    ///
    /// What the origin or the store did wrong; see [`Error`].
    pub async fn set(&self) -> Result<JwkSet, Error> {
        let cached = self
            .cache
            .get(&self.key, async |validators| self.fetch(validators).await)
            .await
            .map_err(|e| match e {
                CacheLookupError::Origin(e) => e,
                CacheLookupError::Store(e) => Error::Store(e.message),
                CacheLookupError::OfflineMiss => Error::Offline,
                CacheLookupError::UnexpectedNotModified => Error::UnexpectedNotModified,
            })?;
        // A store may be shared or persisted: what it gives back is judged again.
        self.read(&cached.body)
    }

    /// The keys a token with `kid` and `alg` may be verified with. A `kid` the set lacks
    /// fetches the set again, as often as the cache's `min_forced_interval` allows.
    ///
    /// # Errors
    ///
    /// [`Error::NoKey`] when none fits, or why the set could not be had.
    pub async fn keys(&self, kid: Option<&str>, alg: &str) -> Result<Vec<Jwk>, Error> {
        let mut set = self.set().await?;
        if let Some(kid) = kid
            && set.by_kid(kid).next().is_none()
            && self
                .cache
                .force(&self.key)
                .await
                .map_err(|e| Error::Store(e.message))?
        {
            set = self.set().await?;
        }
        let keys: Vec<Jwk> = set
            .keys
            .into_iter()
            .filter(|key| kid.is_none_or(|kid| key.kid.as_deref() == Some(kid)))
            .filter(|key| key.allows(KeyPurpose::Signature))
            .filter(|key| key.alg.as_deref().is_none_or(|own| own == alg))
            .collect();
        if keys.is_empty() {
            return Err(Error::NoKey {
                kid: kid.map(str::to_owned),
                alg: alg.to_owned(),
            });
        }
        Ok(keys)
    }

    async fn fetch(&self, validators: Conditional<'_>) -> Result<OriginResponse, Error> {
        let mut headers = vec![(
            "Accept",
            "application/jwk-set+json, application/json".into(),
        )];
        if let Some(etag) = validators.etag {
            headers.push(("If-None-Match", etag.to_owned()));
        }
        if let Some(last_modified) = validators.last_modified {
            headers.push(("If-Modified-Since", last_modified.to_owned()));
        }
        let request = Request {
            url: &self.url,
            headers,
            max_body: self.limits.max_body,
        };
        let response = self.transport.get(&request).await?;
        let mut meta = Meta::new(self.cache.clock().now(), Source::Http);
        meta.max_age = response
            .header("cache-control")
            .and_then(|value| CacheControl::parse(&value).freshness());
        match response.status {
            304 => Ok(OriginResponse::NotModified(meta)),
            200 => {
                self.read(&response.body)?;
                meta.etag = response.header("etag");
                meta.last_modified = response.header("last-modified");
                let Response { body, .. } = response;
                Ok(OriginResponse::Body(CacheEntry { body, meta }))
            }
            status => Err(Error::Status(status)),
        }
    }

    /// `body` as a set within the limits.
    fn read(&self, body: &[u8]) -> Result<JwkSet, Error> {
        if u64::try_from(body.len()).map_or(true, |len| len > self.limits.max_body) {
            return Err(Error::TooLarge(self.limits.max_body));
        }
        let text = core::str::from_utf8(body).map_err(|e| Error::Malformed(e.to_string()))?;
        let set = JwkSet::parse(text).map_err(|e| Error::Malformed(e.to_string()))?;
        if set.keys.len() > self.limits.max_keys {
            return Err(Error::TooManyKeys(self.limits.max_keys));
        }
        Ok(set)
    }
}
