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

//! What a host's HTTP client does for the crate: one GET, answered with whatever status the
//! origin gave.

use core::fmt;

/// A GET of the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The `https` URL; a redirect is an answer, never followed.
    pub url: &'a str,
    /// `If-None-Match`, `If-Modified-Since` and `Accept`.
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
    /// The body, at most [`Request::max_body`] bytes plus whatever the client read beyond.
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

/// Why no answer came: connection, TLS, timeout, a body that could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

/// Performs the GET. No `Send` bound, so a single-threaded host can implement it; a
/// blocking client returns a future that is ready at its first poll.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Transport {
    /// Sends `request` and returns the answer, whatever its status.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when there is no answer.
    async fn get(&self, request: &Request<'_>) -> Result<Response, TransportError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    async fn get(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        (**self).get(request).await
    }
}
