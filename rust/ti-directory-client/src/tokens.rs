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

//! The access token the directory's API takes. For an owner it comes out of a card login
//! through the IDP-Dienst, another product's flow, which this crate does not run: the host
//! runs it, keeps the token and renews it before it expires, and hands it over through
//! [`Tokens`]. This crate tells the host when the directory refuses a token.

use crate::error::Error;
use crate::http::{Request, Response, Transport};

/// Where the directory's access tokens come from, implemented by the host.
///
/// Both methods take `&self`, as [`Transport::send`] does: one source serves every request
/// to the directory, so an implementation keeps its token behind interior mutability.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Tokens {
    /// A token valid for the next request.
    ///
    /// # Errors
    ///
    /// When no token can be had: the directory's own [`Error`] for its steps of a login,
    /// [`Error::Token`] for anything else.
    async fn access_token(&self) -> Result<String, Error>;

    /// The directory refused `token` (HTTP 401): it must not be handed out again.
    async fn refused(&self, token: &str);
}

impl<T: Tokens + ?Sized> Tokens for &T {
    async fn access_token(&self) -> Result<String, Error> {
        (**self).access_token().await
    }

    async fn refused(&self, token: &str) {
        (**self).refused(token).await;
    }
}

/// `request` with a token from `tokens` as its bearer. When the directory answers 401, as
/// it does for an expired or revoked token (`invalid_token`, RFC 6750 §3.1), `tokens` learns that the token was refused and the request goes once more with the
/// next token; the second answer is the response, whatever it is, so that a directory
/// refusing every token costs one extra login and no loop.
///
/// # Errors
///
/// [`Error::Transport`] when the directory does not answer step `what`; what
/// [`Tokens::access_token`] returns when there is no token.
pub async fn send<T: Transport, K: Tokens>(
    transport: &T,
    tokens: &K,
    what: &'static str,
    request: &Request,
) -> Result<Response, Error> {
    let response = send_once(transport, tokens, what, request).await?;
    if response.status != 401 {
        return Ok(response);
    }
    send_once(transport, tokens, what, request).await
}

/// `request` with the next token; a 401 reports that token as refused.
async fn send_once<T: Transport, K: Tokens>(
    transport: &T,
    tokens: &K,
    what: &'static str,
    request: &Request,
) -> Result<Response, Error> {
    let token = tokens.access_token().await?;
    let mut request = request.clone();
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
    request
        .headers
        .push(("authorization".to_owned(), format!("Bearer {token}")));
    let response = transport
        .send(&request)
        .await
        .map_err(|source| Error::Transport { what, source })?;
    if response.status == 401 {
        tokens.refused(&token).await;
    }
    Ok(response)
}
