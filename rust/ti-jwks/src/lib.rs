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

//! JWK Sets from a `jwks_uri` (RFC 7517 §5; OpenID Connect Discovery 1.0 §3, RFC 8414
//! §2): the keys a relying party verifies an issuer's tokens with. The set is fetched
//! through the host's [`http::Transport`], kept in a [`ti_cache::Cache`] and refreshed
//! when a token names a key it lacks.
//!
//! The crate decides, the host carries the bytes: it builds the requests, judges the
//! answers and the keys, and holds no client, no clock and no store of its own. A browser
//! host fetches the set itself and hands its bytes to [`jwz::jwk::JwkSet::parse`]; a
//! blocking host may use the `ureq` feature's transport.
//!
//! The rules:
//!
//! - The set comes from an `https` URL, and a redirect is an error, not followed: the
//!   transport's TLS is what vouches for the origin, so it must be the URL configured.
//! - A body longer than [`Limits::max_body`] or a set of more than [`Limits::max_keys`]
//!   keys is refused before it is stored; so is one that does not parse.
//! - The set stays fresh as long as the origin's `Cache-Control: max-age` says
//!   (RFC 9111 §5.2.2.1), raised to 5 minutes and cut to 24 hours; one hour without one. It is
//!   revalidated with its `ETag` or `Last-Modified` (RFC 9110 §13.1). Past that it is not
//!   served when the origin fails: a key the issuer withdrew must stop verifying
//!   ([`policy`]).
//! - A `kid` the set lacks fetches the set again, at most once a minute, so a stream of
//!   tokens with made-up `kid`s costs the origin one request a minute.
//! - A fetched set replaces the stored one whole: a removed key is gone.
//! - The keys for a token are those with its `kid` (all, when it names none) whose `use`
//!   and `key_ops` allow signatures (RFC 7517 §4.2, §4.3) and whose `alg`, if stated, is
//!   the token's (RFC 7517 §4.4). The caller builds the verifier from one and verifies;
//!   this crate trusts no key for having been fetched.
//!
//! ```
//! # use std::cell::Cell;
//! use ti_cache::{Cache, MemoryCacheStore};
//! use ti_jwks::http::{Request, Response, Transport, TransportError};
//! use ti_jwks::{JwksSource, policy};
//! use ti_types::Timestamp;
//!
//! // Any HTTP client: here, an issuer that serves one key.
//! struct Issuer;
//! impl Transport for Issuer {
//!     async fn get(&self, _: &Request<'_>) -> Result<Response, TransportError> {
//!         Ok(Response {
//!             status: 200,
//!             headers: vec![("Cache-Control".into(), "max-age=600".into())],
//!             body: br#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig",
//!                 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
//!                 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#
//!                 .to_vec(),
//!         })
//!     }
//! }
//!
//! # futures_lite::future::block_on(async {
//! let cache = Cache::new(MemoryCacheStore::new(), || Timestamp(1_700_000_000), policy());
//! let source = JwksSource::new("https://issuer.example/jwks", cache, Issuer)?;
//! let keys = source.keys(Some("k1"), "ES256").await?;
//! assert_eq!(keys[0].kid.as_deref(), Some("k1"));
//! # Ok::<(), ti_jwks::Error>(())
//! # }).unwrap();
//! ```
//!
//! With reqwest the transport is a few lines:
//!
//! ```ignore
//! impl Transport for ReqwestTransport {
//!     async fn get(&self, request: &Request<'_>) -> Result<Response, TransportError> {
//!         let mut req = self.client.get(request.url);
//!         for (name, value) in &request.headers {
//!             req = req.header(*name, value.as_str());
//!         }
//!         let response = req.send().await.map_err(|e| TransportError(e.to_string()))?;
//!         let status = response.status().as_u16();
//!         let headers = response.headers().iter()
//!             .map(|(n, v)| (n.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
//!             .collect();
//!         let body = response.bytes().await.map_err(|e| TransportError(e.to_string()))?;
//!         Ok(Response { status, headers, body: body.to_vec() })
//!     }
//! }
//! ```
//! Its client must not follow redirects (`redirect::Policy::none()`) and should stop
//! reading at [`Request::max_body`](http::Request::max_body).
#![forbid(unsafe_code)]

mod error;
pub mod http;
mod source;
#[cfg(feature = "ureq")]
pub mod ureq;

pub use error::Error;
pub use source::{JwksSource, Limits, policy};
