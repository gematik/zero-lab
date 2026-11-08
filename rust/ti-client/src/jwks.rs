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

//! [`RemoteJwks`]: the keys at a `jwks_uri` (RFC 7517 §5; OpenID Connect Discovery 1.0 §3,
//! RFC 8414 §2) as jwz's [`KeyResolver`], fetched over the `web` profile's agent and kept in a
//! ti-cache store. jwz selects and verifies; this host fetches and caches.
//!
//! The rules:
//!
//! - The set comes from an `https` URL, and a redirect is an error, not followed: the
//!   server certificate vouches for the origin only if it is the URL configured.
//! - A body longer than [`Limits::max_body`] is not read past the limit, and a set of more
//!   than [`Limits::max_keys`] keys or one that does not parse is refused before it is
//!   stored.
//! - The set stays fresh as long as the origin's `Cache-Control` says (RFC 9111 §5.2),
//!   raised to 5 minutes and cut to 24 hours; one hour without one. A stale set is
//!   revalidated with its `ETag` or `Last-Modified` (RFC 9110 §13.1, RFC 9111 §4.3). It is
//!   not served when the origin fails: a key the issuer withdrew must stop verifying.
//! - A `kid` the set lacks fetches the set again, at most once a minute, so a stream of
//!   tokens with made-up `kid`s costs the origin one request a minute.
//! - A fetched set replaces the stored one whole: a removed key is gone.
//! - The candidates for a token are jwz's [`JwkSet::signing_keys`]; none is trusted for
//!   having been fetched, the signature decides (RFC 7515 §5.2, in jwz).

use core::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use jwz::crypto::asynchronous::BoxFuture;
use jwz::header::Header;
use jwz::jwa::SignatureAlgorithm;
use jwz::jwk::{AsyncKeyResolver, Jwk, JwkSet, KeyResolver};
use jwz::{Error as JwzError, ErrorCode};
use ti_cache::{
    Cache, CacheControl, CacheEntry, CacheLookupError, CachePolicy, CacheStore, Conditional,
    FreshnessBounds, Meta, OriginResponse, Source,
};
use ti_types::Timestamp;
use ureq::Agent;

use crate::block_on;
use crate::error::Error;
use crate::http::idp_agent;
use crate::net::Net;

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

/// The cache policy of the rules: the origin's lifetime within 5 minutes and 24 hours, one
/// hour without one, nothing served past it when the origin fails, a forced refresh at most
/// once a minute.
fn policy() -> CachePolicy {
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

/// Why [`RemoteJwks`] has no set to offer. jwz's error carries static text only, so
/// [`RemoteJwks::last_error`] keeps this one for a host that reports the cause.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchError {
    /// No answer from the origin: connection, TLS, timeout, a body that could not be read.
    Transport(String),
    /// An answer other than 200 or 304, a redirect among them.
    Status(u16),
    /// The body is longer than the limit.
    TooLarge(u64),
    /// The set holds more keys than the limit.
    TooManyKeys(usize),
    /// The body is not a JWK Set.
    Malformed(String),
    /// The origin answered "not modified" to a request that held no validator.
    UnexpectedNotModified,
    /// The store failed.
    Store(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Transport(message) | FetchError::Malformed(message) => {
                write!(f, "JWK Set: {message}")
            }
            FetchError::Status(status) => write!(f, "JWK Set: HTTP status {status}"),
            FetchError::TooLarge(limit) => write!(f, "JWK Set: longer than {limit} bytes"),
            FetchError::TooManyKeys(limit) => write!(f, "JWK Set: more than {limit} keys"),
            FetchError::UnexpectedNotModified => {
                f.write_str("JWK Set: not modified, but nothing is stored")
            }
            FetchError::Store(message) => write!(f, "JWK Set cache: {message}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl FetchError {
    /// The error jwz passes on from [`Jws::verify_with`](jwz::jws::Jws::verify_with).
    fn to_jwz(&self) -> JwzError {
        let context = match self {
            FetchError::Transport(_) => "JWK Set origin not reached",
            FetchError::Status(_) => "JWK Set origin answered other than 200 or 304",
            FetchError::TooLarge(_) => "JWK Set longer than the limit",
            FetchError::TooManyKeys(_) => "JWK Set holds more keys than the limit",
            FetchError::Malformed(_) => "JWK Set malformed",
            FetchError::UnexpectedNotModified => "JWK Set origin answered 304 unasked",
            FetchError::Store(_) => "JWK Set cache failed",
        };
        JwzError::new(ErrorCode::KeyUnavailable, context)
    }
}

/// A GET of the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The `https` URL; a redirect is an answer, never followed.
    pub url: &'a str,
    /// `Accept`, `If-None-Match` and `If-Modified-Since`.
    pub headers: Vec<(&'static str, String)>,
    /// Stop reading the body past this many bytes: the set is refused anyway.
    pub max_body: u64,
}

/// The origin's answer, any status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The headers, names in any case; several of a name are several entries.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// The values of `name`, joined with `, ` as RFC 9110 §5.3 combines field lines.
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

/// What [`RemoteJwks`] asks of HTTP: one blocking GET, answered with whatever status the
/// origin gave. [`UreqTransport`] is the host's; a test passes a scripted one to
/// [`RemoteJwks::with_transport`].
pub trait Transport {
    /// Sends `request` and returns the answer, whatever its status.
    ///
    /// # Errors
    ///
    /// [`FetchError::Transport`] when there is no answer, [`FetchError::TooLarge`] for a body
    /// longer than [`Request::max_body`].
    fn get(&self, request: &Request<'_>) -> Result<Response, FetchError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn get(&self, request: &Request<'_>) -> Result<Response, FetchError> {
        (**self).get(request)
    }
}

/// [`Transport`] over an agent that follows no redirect and turns no status into an error,
/// such as [`idp_agent`]'s.
#[derive(Clone, Debug)]
pub struct UreqTransport {
    agent: Agent,
}

impl UreqTransport {
    /// Over `agent`, configured as the type's documentation says.
    pub fn new(agent: Agent) -> UreqTransport {
        UreqTransport { agent }
    }
}

impl Transport for UreqTransport {
    fn get(&self, request: &Request<'_>) -> Result<Response, FetchError> {
        let failed = |e: ureq::Error| FetchError::Transport(e.to_string());
        let mut req = self.agent.get(request.url);
        for (name, value) in &request.headers {
            req = req.header(*name, value.as_str());
        }
        let mut response = req.call().map_err(failed)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(request.max_body)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => FetchError::TooLarge(request.max_body),
                e => failed(e),
            })?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// The keys at one `jwks_uri`, a [`KeyResolver`] for [`Jws::verify_with`]. Every call blocks,
/// as ti-client's operations do; the store must too (a [`FileCache`](crate::FileCache) or
/// a [`ti_cache::MemoryCacheStore`]), since its futures are run with [`block_on`].
///
/// [`Jws::verify_with`]: jwz::jws::Jws::verify_with
pub struct RemoteJwks<S, N, T = UreqTransport> {
    url: String,
    key: String,
    cache: Cache<S, N>,
    transport: T,
    limits: Limits,
    last_error: Mutex<Option<FetchError>>,
}

impl<S: fmt::Debug, N, T> fmt::Debug for RemoteJwks<S, N, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteJwks")
            .field("url", &self.url)
            .field("cache", &self.cache)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<S: CacheStore, N: Fn() -> Timestamp> RemoteJwks<S, N> {
    /// The set at `url`, fetched with `net`'s proxy, CA and timeouts over the agent of the
    /// IDP-Dienst ([`idp_agent`]: the `web` profile whatever `-k` says, no redirect
    /// followed), kept in `store`, aged by `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for a URL that is not `https`, or an unusable proxy or CA file or
    /// directory.
    pub fn new(url: &str, net: &Net, store: S, now: N) -> Result<Self, Error> {
        check_https(url)?;
        Self::with_transport(url, UreqTransport::new(idp_agent(net)?), store, now)
    }
}

impl<S: CacheStore, N: Fn() -> Timestamp, T: Transport> RemoteJwks<S, N, T> {
    /// [`new`](RemoteJwks::new) over another transport, such as a test's scripted origin.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for a URL that is not `https`.
    pub fn with_transport(url: &str, transport: T, store: S, now: N) -> Result<Self, Error> {
        check_https(url)?;
        Ok(RemoteJwks {
            url: url.to_owned(),
            key: format!("ti-client/v1/jwks/{url}"),
            cache: Cache::new(store, now, policy()),
            transport,
            limits: Limits::default(),
            last_error: Mutex::new(None),
        })
    }

    /// This resolver with other limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The current set: the stored one while fresh, else what the origin answers.
    ///
    /// # Errors
    ///
    /// What the origin or the store did wrong; see [`FetchError`].
    pub fn set(&self) -> Result<JwkSet, FetchError> {
        let cached = block_on(
            self.cache
                .get(&self.key, async |validators| self.fetch(validators)),
        )
        .map_err(|e| match e {
            CacheLookupError::Origin(e) => e,
            CacheLookupError::Store(e) => FetchError::Store(e.message),
            // The policy is never offline; a store that claims so has failed.
            CacheLookupError::OfflineMiss => FetchError::Store("offline".into()),
            CacheLookupError::UnexpectedNotModified => FetchError::UnexpectedNotModified,
        })?;
        // A store may be shared or persisted: what it gives back is judged again.
        self.read(&cached.body)
    }

    /// The candidates for a JWS whose header names `kid` (or none) with `alg`
    /// ([`JwkSet::signing_keys`]), none when no key fits. A `kid` the set lacks fetches the
    /// set again, at most once a minute.
    ///
    /// # Errors
    ///
    /// Why the set could not be had.
    pub fn keys(&self, kid: Option<&str>, alg: SignatureAlgorithm) -> Result<Vec<Jwk>, FetchError> {
        let mut set = self.set()?;
        if let Some(kid) = kid
            && set.by_kid(kid).next().is_none()
            && block_on(self.cache.force(&self.key)).map_err(|e| FetchError::Store(e.message))?
        {
            set = self.set()?;
        }
        Ok(set.signing_keys(kid, alg).cloned().collect())
    }

    /// Why the last resolution failed, for a host that reports more than jwz's
    /// [`ErrorCode::KeyUnavailable`]; cleared by one that succeeds.
    pub fn last_error(&self) -> Option<FetchError> {
        self.last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn fetch(&self, validators: Conditional<'_>) -> Result<OriginResponse, FetchError> {
        let mut headers = vec![(
            "Accept",
            "application/jwk-set+json, application/json".to_owned(),
        )];
        if let Some(etag) = validators.etag {
            headers.push(("If-None-Match", etag.to_owned()));
        }
        if let Some(last_modified) = validators.last_modified {
            headers.push(("If-Modified-Since", last_modified.to_owned()));
        }
        let response = self.transport.get(&Request {
            url: &self.url,
            headers,
            max_body: self.limits.max_body,
        })?;
        let mut meta = Meta::new(self.cache.now(), Source::Http);
        meta.max_age = response
            .header("cache-control")
            .and_then(|value| CacheControl::parse(&value).freshness());
        match response.status {
            304 => Ok(OriginResponse::NotModified(meta)),
            200 => {
                self.read(&response.body)?;
                meta.etag = response.header("etag");
                meta.last_modified = response.header("last-modified");
                Ok(OriginResponse::Body(CacheEntry {
                    body: response.body,
                    meta,
                }))
            }
            status => Err(FetchError::Status(status)),
        }
    }

    /// `body` as a set within the limits.
    fn read(&self, body: &[u8]) -> Result<JwkSet, FetchError> {
        if u64::try_from(body.len()).map_or(true, |len| len > self.limits.max_body) {
            return Err(FetchError::TooLarge(self.limits.max_body));
        }
        let text = core::str::from_utf8(body).map_err(|e| FetchError::Malformed(e.to_string()))?;
        let set = JwkSet::parse(text).map_err(|e| FetchError::Malformed(e.to_string()))?;
        if set.keys.len() > self.limits.max_keys {
            return Err(FetchError::TooManyKeys(self.limits.max_keys));
        }
        Ok(set)
    }

    fn resolved(&self, header: &Header, alg: SignatureAlgorithm) -> Result<Vec<Jwk>, JwzError> {
        let result = self.keys(header.kid(), alg);
        let mut last = self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(keys) => {
                *last = None;
                Ok(keys)
            }
            Err(error) => {
                let code = error.to_jwz();
                *last = Some(error);
                Err(code)
            }
        }
    }
}

impl<S: CacheStore, N: Fn() -> Timestamp, T: Transport> KeyResolver for RemoteJwks<S, N, T> {
    fn resolve(&self, header: &Header, alg: SignatureAlgorithm) -> Result<Vec<Jwk>, JwzError> {
        self.resolved(header, alg)
    }
}

/// For a verifier written against the asynchronous API: the fetch blocks, so the future is
/// ready when made.
impl<S: CacheStore, N: Fn() -> Timestamp, T: Transport> AsyncKeyResolver for RemoteJwks<S, N, T> {
    fn resolve_async<'a>(
        &'a self,
        header: &'a Header,
        alg: SignatureAlgorithm,
    ) -> BoxFuture<'a, Result<Vec<Jwk>, JwzError>> {
        let keys = self.resolved(header, alg);
        Box::pin(async move { keys })
    }
}

/// The server certificate vouches for the origin only if it is the URL configured, and only
/// over TLS.
fn check_https(url: &str) -> Result<(), Error> {
    let https = url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
    if !https || url.len() == 8 {
        return Err(Error::Setup(format!(
            "the JWK Set URL must be https: {url}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use jwz::crypto::rustcrypto::RustCrypto;
    use jwz::header::HeaderParams;
    use jwz::jwa::Registry;
    use jwz::jws::{self, Jws};
    use jwz::keys::SoftwareKey;
    use jwz::profile::Profile;
    use std::sync::Arc;
    use ti_cache::MemoryCacheStore;

    use super::*;

    const T0: Timestamp = Timestamp(1_700_000_000);
    const URL: &str = "https://issuer.example/jwks";
    const ES256: SignatureAlgorithm = SignatureAlgorithm::ES256;

    /// An origin that answers from a script and records the headers of each request.
    #[derive(Default)]
    struct Origin {
        answers: RefCell<VecDeque<Result<Response, FetchError>>>,
        asked: RefCell<Vec<Vec<(&'static str, String)>>>,
    }

    impl Origin {
        fn then(&self, answer: Response) -> &Self {
            self.answers.borrow_mut().push_back(Ok(answer));
            self
        }

        fn fails(&self, error: &str) -> &Self {
            self.answers
                .borrow_mut()
                .push_back(Err(FetchError::Transport(error.into())));
            self
        }

        fn requests(&self) -> usize {
            self.asked.borrow().len()
        }
    }

    impl Transport for Origin {
        fn get(&self, request: &Request<'_>) -> Result<Response, FetchError> {
            assert_eq!(request.url, URL);
            self.asked.borrow_mut().push(request.headers.clone());
            self.answers
                .borrow_mut()
                .pop_front()
                .expect("the origin was asked more often than scripted")
        }
    }

    struct TestClock(Cell<Timestamp>);

    impl TestClock {
        fn new() -> TestClock {
            TestClock(Cell::new(T0))
        }

        fn now(&self) -> Timestamp {
            self.0.get()
        }

        fn advance(&self, by: Duration) {
            self.0.set(self.0.get() + by);
        }
    }

    const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    fn key(kid: &str, members: &str) -> String {
        format!(r#"{{"kty":"EC","crv":"P-256","kid":"{kid}","x":"{X}","y":"{Y}"{members}}}"#)
    }

    fn set(keys: &[String]) -> Vec<u8> {
        format!(r#"{{"keys":[{}]}}"#, keys.join(",")).into_bytes()
    }

    fn answer(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body,
        }
    }

    fn ok(body: Vec<u8>, headers: &[(&str, &str)]) -> Response {
        answer(200, headers, body)
    }

    fn remote<'a>(
        origin: &'a Origin,
        clock: &'a TestClock,
    ) -> RemoteJwks<MemoryCacheStore, impl Fn() -> Timestamp + 'a, &'a Origin> {
        RemoteJwks::with_transport(URL, origin, MemoryCacheStore::new(), move || clock.now())
            .unwrap()
    }

    fn kids(keys: &[Jwk]) -> Vec<&str> {
        keys.iter().filter_map(|k| k.kid.as_deref()).collect()
    }

    /// The server certificate vouches for the origin only if it is the URL configured: the
    /// set comes from an `https` URL, and a redirect is an answer refused, not followed.
    #[test]
    fn the_set_comes_from_an_https_url_and_a_redirect_is_an_error() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        for url in [
            "http://issuer.example/jwks",
            "https://",
            "issuer.example",
            "ftp://x",
        ] {
            assert!(
                matches!(
                    RemoteJwks::with_transport(url, &origin, MemoryCacheStore::new(), || {
                        clock.now()
                    }),
                    Err(Error::Setup(_))
                ),
                "{url}"
            );
        }
        assert!(
            RemoteJwks::with_transport(
                "HTTPS://issuer.example/jwks",
                &origin,
                MemoryCacheStore::new(),
                || clock.now()
            )
            .is_ok()
        );
        origin
            .then(answer(
                302,
                &[("Location", "https://elsewhere.example/")],
                Vec::new(),
            ))
            .then(answer(500, &[], Vec::new()));
        let remote = remote(&origin, &clock);
        assert_eq!(remote.set(), Err(FetchError::Status(302)));
        assert_eq!(remote.set(), Err(FetchError::Status(500)));
        assert_eq!(origin.requests(), 2);
    }

    /// What does not fit the limits or does not parse is refused and never stored, so the
    /// next lookup asks again; the transport is told where to stop reading.
    #[test]
    fn a_set_over_the_limits_or_not_a_set_is_refused_and_not_stored() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock).with_limits(Limits {
            max_body: 300,
            max_keys: 1,
        });
        origin
            .then(ok(vec![b' '; 301], &[]))
            .then(ok(set(&[key("a", ""), key("b", "")]), &[]))
            .then(ok(b"{\"keys\":".to_vec(), &[]))
            .then(ok(vec![0xff], &[]))
            .then(ok(set(&[key("a", "")]), &[]));
        assert_eq!(remote.set(), Err(FetchError::TooLarge(300)));
        assert_eq!(remote.set(), Err(FetchError::TooManyKeys(1)));
        assert!(matches!(remote.set(), Err(FetchError::Malformed(_))));
        assert!(matches!(remote.set(), Err(FetchError::Malformed(_))));
        assert_eq!(remote.set().unwrap().keys.len(), 1);
        assert_eq!(origin.requests(), 5);
    }

    /// The default limits: 64 KiB and 100 keys.
    #[test]
    fn the_default_limits_are_64_kib_and_100_keys() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        let keys: Vec<String> = (0..101).map(|i| key(&i.to_string(), "")).collect();
        origin
            .then(ok(vec![b' '; 64 * 1024 + 1], &[]))
            .then(ok(set(&keys), &[]))
            .then(ok(set(&keys[..100]), &[]));
        assert_eq!(remote.set(), Err(FetchError::TooLarge(64 * 1024)));
        assert_eq!(remote.set(), Err(FetchError::TooManyKeys(100)));
        assert_eq!(remote.set().unwrap().keys.len(), 100);
    }

    /// RFC 9111 §5.2: the set is fresh for the origin's `Cache-Control`, raised to 5
    /// minutes (`no-cache` among the shorter) and cut to 24 hours; one hour without one.
    #[test]
    fn rfc_9111_5_2_the_set_is_fresh_for_the_origins_cache_control_within_bounds() {
        for (cache_control, lifetime) in [
            (Some("max-age=600"), 600),
            (Some("no-cache"), 300),
            (Some("max-age=999999"), 86_400),
            (None, 3_600),
        ] {
            let (origin, clock) = (Origin::default(), TestClock::new());
            let remote = remote(&origin, &clock);
            let headers: Vec<(&str, &str)> = cache_control
                .map(|v| vec![("Cache-Control", v)])
                .unwrap_or_default();
            origin
                .then(ok(set(&[key("a", "")]), &headers))
                .then(ok(set(&[key("a", "")]), &headers));
            remote.set().unwrap();
            clock.advance(Duration::from_secs(lifetime - 1));
            remote.set().unwrap();
            assert_eq!(origin.requests(), 1, "{cache_control:?}: fresh");
            clock.advance(Duration::from_secs(1));
            remote.set().unwrap();
            assert_eq!(
                origin.requests(),
                2,
                "{cache_control:?}: stale after {lifetime} s"
            );
        }
    }

    /// RFC 9110 §5.3: several field lines of one name are one value, joined with commas; a
    /// `Cache-Control` split over two lines still counts.
    #[test]
    fn rfc_9110_5_3_field_lines_of_one_name_are_one_value() {
        let response = answer(
            200,
            &[
                ("Cache-Control", "public"),
                ("ETag", "\"v1\""),
                ("cache-control", "max-age=600"),
            ],
            Vec::new(),
        );
        assert_eq!(
            response.header("CACHE-CONTROL").as_deref(),
            Some("public, max-age=600")
        );
        assert_eq!(response.header("x-missing"), None);
    }

    /// RFC 9110 §13.1.1, §13.1.3 and RFC 9111 §4.3: a stale set is revalidated with its
    /// `ETag` and `Last-Modified`, and a 304 keeps it for the lifetime the 304 states.
    #[test]
    fn rfc_9110_13_1_a_stale_set_is_revalidated_with_its_validators() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        origin
            .then(ok(
                set(&[key("a", "")]),
                &[
                    ("ETag", "\"v1\""),
                    ("Last-Modified", "Tue, 03 Nov 2026 10:00:00 GMT"),
                    ("Cache-Control", "max-age=600"),
                ],
            ))
            .then(answer(304, &[("cache-control", "max-age=900")], Vec::new()));
        remote.set().unwrap();
        clock.advance(Duration::from_secs(600));
        assert_eq!(kids(&remote.set().unwrap().keys), ["a"]);
        let second = origin.asked.borrow()[1].clone();
        assert!(
            second.contains(&("If-None-Match", "\"v1\"".into())),
            "{second:?}"
        );
        assert!(
            second.contains(&("If-Modified-Since", "Tue, 03 Nov 2026 10:00:00 GMT".into())),
            "{second:?}"
        );
        clock.advance(Duration::from_secs(899));
        remote.set().unwrap();
        assert_eq!(origin.requests(), 2, "the 304's max-age counts");
    }

    /// RFC 9111 §4.3.3: a 304 to a request that held no validator has nothing to keep.
    #[test]
    fn rfc_9111_4_3_3_a_304_without_a_stored_set_is_an_error() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        origin.then(answer(304, &[], Vec::new()));
        assert_eq!(remote.set(), Err(FetchError::UnexpectedNotModified));
    }

    /// A withdrawn key must stop verifying: past its lifetime the set is not served when the
    /// origin fails, and the resolver answers `KeyUnavailable`, the cause kept for the host.
    #[test]
    fn a_stale_set_is_not_served_when_the_origin_fails() {
        let signer = Signer::new("a");
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        origin
            .then(ok(signer.set(), &[]))
            .then(answer(503, &[], Vec::new()))
            .fails("down");
        assert_eq!(signer.verify(&remote), Ok(b"hello".to_vec()));
        assert_eq!(remote.last_error(), None);
        clock.advance(Duration::from_hours(1));
        let error = signer.verify(&remote).unwrap_err();
        assert_eq!(error.code(), ErrorCode::KeyUnavailable);
        assert_eq!(remote.last_error(), Some(FetchError::Status(503)));
        let error = signer.verify(&remote).unwrap_err();
        assert_eq!(error.code(), ErrorCode::KeyUnavailable);
        assert_eq!(
            remote.last_error(),
            Some(FetchError::Transport("down".into()))
        );
    }

    /// A `kid` the set lacks fetches it again, at most once a minute: made-up `kid`s cost the
    /// origin one request a minute.
    #[test]
    fn an_unknown_kid_fetches_the_set_again_at_most_once_a_minute() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        let day = [("Cache-Control", "max-age=86400")];
        origin
            .then(ok(set(&[key("old", "")]), &day))
            .then(ok(set(&[key("old", ""), key("new", "")]), &day));
        assert_eq!(kids(&remote.keys(Some("old"), ES256).unwrap()), ["old"]);
        assert_eq!(kids(&remote.keys(Some("new"), ES256).unwrap()), ["new"]);
        assert_eq!(origin.requests(), 2, "rotation seen at once");

        for _ in 0..100 {
            assert_eq!(remote.keys(Some("made-up"), ES256).unwrap().len(), 0);
        }
        assert_eq!(
            origin.requests(),
            2,
            "within the minute of the last refresh"
        );
        clock.advance(Duration::from_mins(1));
        origin.then(ok(set(&[key("new", "")]), &[]));
        assert_eq!(remote.keys(Some("made-up"), ES256).unwrap().len(), 0);
        assert_eq!(origin.requests(), 3, "a minute later, one more");
        assert_eq!(
            remote.keys(None, ES256).unwrap().len(),
            1,
            "no kid, no refresh"
        );
        assert_eq!(origin.requests(), 3);
    }

    /// A fetched set replaces the stored one whole.
    #[test]
    fn a_fetched_set_replaces_the_stored_one_and_a_removed_key_is_gone() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        origin
            .then(ok(set(&[key("a", ""), key("b", "")]), &[]))
            .then(ok(set(&[key("b", "")]), &[]))
            .then(ok(set(&[key("b", "")]), &[]));
        assert_eq!(remote.keys(Some("a"), ES256).unwrap().len(), 1);
        clock.advance(Duration::from_hours(1));
        // The stale set is replaced; "a" is then unknown, which asks once more.
        assert_eq!(remote.keys(Some("a"), ES256).unwrap().len(), 0);
        assert_eq!(origin.requests(), 3);
    }

    /// RFC 7517 §4.2, RFC 7517 §4.3, RFC 7517 §4.4 and RFC 7517 §5: the candidates for a
    /// token are the keys of the set with its `kid` whose `use` and `key_ops` allow
    /// signatures and whose `alg`, if stated, is the token's.
    #[test]
    fn rfc_7517_4_4_the_keys_fit_the_tokens_kid_alg_and_use() {
        let (origin, clock) = (Origin::default(), TestClock::new());
        let remote = remote(&origin, &clock);
        origin.then(ok(
            set(&[
                key("k", r#","use":"sig","alg":"ES256""#),
                key("k", r#","use":"enc""#),
                key("k", r#","alg":"ES384""#),
                key("k", r#","key_ops":["encrypt"]"#),
                key("k", r#","key_ops":["verify"]"#),
                key("other", ""),
            ]),
            &[],
        ));
        let keys = remote.keys(Some("k"), ES256).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].alg.as_deref(), Some("ES256"));
        assert_eq!(
            keys[1].key_ops.as_deref(),
            Some(&["verify".to_string()][..])
        );
        assert_eq!(remote.keys(None, ES256).unwrap().len(), 3);
    }

    #[test]
    fn a_resolver_is_shared_between_threads() {
        fn send_and_sync<T: Send + Sync>() {}
        send_and_sync::<RemoteJwks<MemoryCacheStore, fn() -> Timestamp>>();
    }

    /// A key of jwz's default backend and the strict profile it signs under.
    struct Signer {
        key: SoftwareKey<RustCrypto>,
        backend: Arc<RustCrypto>,
        registry: Registry,
        profile: Profile,
    }

    impl Signer {
        fn new(kid: &str) -> Signer {
            let registry = Registry::standard();
            let backend = Arc::new(RustCrypto::new());
            let key = SoftwareKey::generate(ES256, &registry, Arc::clone(&backend))
                .unwrap()
                .with_kid(kid);
            Signer {
                key,
                backend,
                registry,
                profile: Profile::strict(),
            }
        }

        /// A set with this key's public half.
        fn set(&self) -> Vec<u8> {
            format!(r#"{{"keys":[{}]}}"#, self.key.public_jwk().to_json()).into_bytes()
        }

        fn parsed(&self) -> Jws<jws::Unverified> {
            let token = jws::sign(
                b"hello",
                HeaderParams::new(),
                &self.key,
                &self.profile.policy,
                &self.registry,
            )
            .unwrap();
            Jws::parse(&token, &self.profile.policy, &self.registry).unwrap()
        }

        /// The payload of a token this key signed, verified with the keys `resolver` offers.
        fn verify(&self, resolver: &dyn KeyResolver) -> Result<Vec<u8>, JwzError> {
            self.parsed()
                .verify_with(resolver, &self.registry, &self.backend)
                .map(|verified| verified.payload().to_vec())
        }

        fn verify_async(&self, resolver: &dyn AsyncKeyResolver) -> Result<Vec<u8>, JwzError> {
            block_on(
                self.parsed()
                    .verify_with_async(resolver, &self.registry, &self.backend),
            )
            .map(|verified| verified.payload().to_vec())
        }
    }

    /// The real ureq path against a loopback TLS server with the Konnektor tests' CA
    /// (`ti-connector-client/tests/tls`): the agent is [`idp_agent`]'s settings over a
    /// rustls configuration that trusts that CA in place of the `web` profile, whose rules
    /// ti-tls proves.
    mod loopback {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener};
        use std::sync::Mutex;

        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
        use rustls::{
            ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, ServerConnection,
            SignatureScheme, StreamOwned,
        };

        use super::*;
        use crate::http::redirectless_agent;

        const CA: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/ca.pem");
        const SERVER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server.pem");
        const SERVER_KEY: &[u8] =
            include_bytes!("../../ti-connector-client/tests/tls/server-key.pem");

        fn provider() -> Arc<rustls::crypto::CryptoProvider> {
            Arc::new(rustls::crypto::ring::default_provider())
        }

        /// The test server's certificate names `konnektor.test` only; the loopback URL
        /// names an address. Everything else of the chain is checked as usual.
        #[derive(Debug)]
        struct AsKonnektorTest(Arc<WebPkiServerVerifier>);

        impl ServerCertVerifier for AsKonnektorTest {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                intermediates: &[CertificateDer<'_>],
                _: &ServerName<'_>,
                ocsp_response: &[u8],
                now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                let name = ServerName::try_from("konnektor.test").unwrap();
                self.0
                    .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                self.0.verify_tls12_signature(message, cert, dss)
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                self.0.verify_tls13_signature(message, cert, dss)
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.0.supported_verify_schemes()
            }
        }

        fn client_config() -> Arc<ClientConfig> {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_slice(CA).unwrap())
                .unwrap();
            let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .unwrap();
            Arc::new(
                ClientConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AsKonnektorTest(verifier)))
                    .with_no_client_auth(),
            )
        }

        /// curl's defaults, without a proxy whatever the environment of the test run says.
        fn net() -> Net {
            Net {
                insecure: false,
                cacert: Vec::new(),
                capath: None,
                proxy: Some(String::new()),
                noproxy: None,
                connect_timeout: Duration::from_secs(10),
                max_time: Duration::from_mins(1),
                retry: 0,
                user_agent: "ti-client-test".into(),
            }
        }

        /// A TLS server on a loopback port answering each connection with the next of
        /// `answers`, counting the connections it accepted.
        struct Server {
            addr: SocketAddr,
            connections: Arc<Mutex<usize>>,
        }

        impl Server {
            fn start(answers: Vec<String>) -> Server {
                let config = Arc::new(
                    ServerConfig::builder_with_provider(provider())
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(
                            vec![CertificateDer::from_pem_slice(SERVER).unwrap()],
                            PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
                        )
                        .unwrap(),
                );
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = listener.local_addr().unwrap();
                let connections = Arc::new(Mutex::new(0));
                let counted = Arc::clone(&connections);
                std::thread::spawn(move || {
                    let mut answers = answers.into_iter();
                    for socket in listener.incoming() {
                        let Ok(socket) = socket else { continue };
                        *counted.lock().unwrap() += 1;
                        let Some(answer) = answers.next() else {
                            continue;
                        };
                        let Ok(connection) = ServerConnection::new(Arc::clone(&config)) else {
                            continue;
                        };
                        let mut tls = StreamOwned::new(connection, socket);
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            match tls.read(&mut byte) {
                                Ok(1) => head.push(byte[0]),
                                _ => break,
                            }
                        }
                        let _ = tls.write_all(answer.as_bytes());
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    }
                });
                Server { addr, connections }
            }

            fn url(&self, scheme: &str) -> String {
                format!("{scheme}://{}/jwks", self.addr)
            }

            fn connections(&self) -> usize {
                *self.connections.lock().unwrap()
            }
        }

        fn ok(body: &[u8]) -> String {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            )
        }

        fn transport() -> UreqTransport {
            UreqTransport::new(redirectless_agent(&net(), client_config()).unwrap())
        }

        /// An `http://` URL is refused before any connection is made, and a redirect from
        /// the configured origin is an error, its target never asked.
        #[test]
        fn http_is_refused_unconnected_and_a_redirect_is_not_followed() {
            let clock = TestClock::new();
            let plain = Server::start(Vec::new());
            assert!(matches!(
                RemoteJwks::with_transport(
                    &plain.url("http"),
                    transport(),
                    MemoryCacheStore::new(),
                    || clock.now()
                ),
                Err(Error::Setup(_))
            ));
            assert!(matches!(
                RemoteJwks::new(&plain.url("http"), &net(), MemoryCacheStore::new(), || {
                    clock.now()
                }),
                Err(Error::Setup(_))
            ));
            assert_eq!(plain.connections(), 0);

            let target = Server::start(vec![ok(&set(&[key("a", "")]))]);
            let origin = Server::start(vec![format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                target.url("https")
            )]);
            let remote = RemoteJwks::with_transport(
                &origin.url("https"),
                transport(),
                MemoryCacheStore::new(),
                || clock.now(),
            )
            .unwrap();
            assert_eq!(remote.set(), Err(FetchError::Status(302)));
            assert_eq!(origin.connections(), 1);
            assert_eq!(target.connections(), 0);
        }

        /// The transport stops reading at the limit: a long body is refused, not buffered.
        #[test]
        fn the_ureq_transport_stops_reading_at_the_limit() {
            let origin = Server::start(vec![ok(&vec![b' '; 2048])]);
            let request = Request {
                url: &origin.url("https"),
                headers: Vec::new(),
                max_body: 1024,
            };
            assert_eq!(transport().get(&request), Err(FetchError::TooLarge(1024)));
        }

        /// RFC 7515 §5.2 step 8 through the resolver over TLS: a token signed by a key the
        /// origin serves verifies, one signed by a key it does not serve is refused.
        #[test]
        fn rfc_7515_5_2_a_token_verifies_with_the_served_key_only() {
            let (served, unserved) = (Signer::new("k1"), Signer::new("k2"));
            // The unserved key's kid is unknown and fetches the set once more.
            let origin = Server::start(vec![ok(&served.set()), ok(&served.set())]);
            let clock = TestClock::new();
            let remote = RemoteJwks::with_transport(
                &origin.url("https"),
                transport(),
                MemoryCacheStore::new(),
                || clock.now(),
            )
            .unwrap();
            assert_eq!(served.verify(&remote), Ok(b"hello".to_vec()));
            assert_eq!(
                unserved.verify(&remote).unwrap_err().code(),
                ErrorCode::VerificationFailed
            );
            assert_eq!(served.verify_async(&remote), Ok(b"hello".to_vec()));
            assert_eq!(origin.connections(), 2);
        }
    }
}
