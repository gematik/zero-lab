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

//! Why no keys came.

use crate::http::TransportError;

/// Why [`crate::JwksSource`] has no keys to offer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The URL is not `https`.
    #[error("the JWK Set URL must be https: {0}")]
    NotHttps(String),
    /// No answer from the origin.
    #[error("JWK Set: {0}")]
    Transport(#[from] TransportError),
    /// An answer other than 200 or 304, a redirect among them.
    #[error("JWK Set: HTTP status {0}")]
    Status(u16),
    /// The body is longer than the limit.
    #[error("JWK Set: longer than {0} bytes")]
    TooLarge(u64),
    /// The set holds more keys than the limit.
    #[error("JWK Set: more than {0} keys")]
    TooManyKeys(usize),
    /// The body is not a JWK Set.
    #[error("JWK Set: {0}")]
    Malformed(String),
    /// The origin answered "not modified" to a request that held no validator.
    #[error("JWK Set: not modified, but nothing is stored")]
    UnexpectedNotModified,
    /// The cache is offline and holds no set.
    #[error("JWK Set: offline and nothing stored")]
    Offline,
    /// The cache's store failed.
    #[error("JWK Set cache: {0}")]
    Store(String),
    /// No key in the set fits the token.
    #[error("no key in the JWK Set for kid {kid:?} and alg {alg}")]
    NoKey {
        /// The token's `kid`.
        kid: Option<String>,
        /// The token's `alg`.
        alg: String,
    },
}
