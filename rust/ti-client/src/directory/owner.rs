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

//! The owner login by card, two products' flows joined: the FHIR-Directory's redirect and
//! sign-in (ti-directory-client) around the IDP-Dienst's Authenticator-Modul flow
//! (ti-idpd-client). No product client depends on another (decision-15), so the host joins
//! them here and keeps the owner token for the directory's API ([`OwnerTokens`]).

use std::cell::RefCell;

use ti_directory_client::tokens::Tokens;
use ti_directory_client::{AccessToken, Directory, owner};
use ti_idpd_client::Idp;
use ti_idpd_client::authenticator::{self, Authenticated, Identity};
use ti_idpd_client::trust::CertificateTrust;
use ti_pki::Timestamp;

/// Seconds before its expiry that a token is renewed: one handed out must still be valid
/// when its request reaches the directory, over a slow network and with the directory's
/// clock a little ahead of this one.
pub const RENEW_BEFORE: u64 = 60;

/// A token the directory issued, when it expires by this host's clock, and how it was had.
#[derive(Clone, Debug)]
pub struct Issued<R> {
    /// The token.
    pub token: AccessToken,
    /// When it expires, from this host's clock and `expires_in`.
    pub expires_at: Timestamp,
    /// How it was had.
    pub how: R,
}

/// What a card login went through besides the token.
#[derive(Clone, Debug)]
pub struct ByCard {
    /// The IDP-Dienst authorization URL the directory sent the card to.
    pub authorization_url: String,
    /// The IDP-Dienst flow's result: discovery document, challenge claims, warnings.
    pub authenticated: Authenticated,
}

/// The step that failed, by product: each keeps its own kinds of error.
#[derive(Debug)]
pub enum OwnerError {
    /// A step at the directory.
    Directory(ti_directory_client::Error),
    /// A step of the IDP-Dienst flow.
    Idpd(ti_idpd_client::Error),
}

impl From<ti_directory_client::Error> for OwnerError {
    fn from(error: ti_directory_client::Error) -> OwnerError {
        OwnerError::Directory(error)
    }
}

impl From<ti_idpd_client::Error> for OwnerError {
    fn from(error: ti_idpd_client::Error) -> OwnerError {
        OwnerError::Idpd(error)
    }
}

/// The owner token of `identity` over `transport`: the directory's redirect, the
/// IDP-Dienst flow at the directory's own IDP-Dienst, the sign-in with its code. `now` is
/// read for each token's validity, `trust` decides about the IDP's certificates.
///
/// # Errors
///
/// The first failing step's error.
pub async fn login<T, C>(
    transport: &T,
    directory: &Directory,
    identity: &Identity<'_>,
    now: impl Fn() -> Timestamp,
    trust: &C,
) -> Result<Issued<ByCard>, OwnerError>
where
    T: ti_directory_client::http::Transport + ti_idpd_client::http::Transport,
    C: CertificateTrust,
{
    let authorization_url = owner::authorization_url(
        directory,
        &send(transport, "owner-authenticate", &owner::start(directory)).await?,
    )?;
    let authenticated = authenticator::authenticate(
        transport,
        &Idp::new(directory.idp_url()),
        identity,
        &authorization_url,
        &now,
        trust,
    )
    .await?;
    let request = owner::sign_in(directory, &authenticated.redirect.url)?;
    let token = owner::token(&send(transport, "signin-gematik-idp-dienst", &request).await?)?;
    Ok(Issued {
        expires_at: Timestamp(now().0.saturating_add(token.expires_in)),
        token,
        how: ByCard {
            authorization_url,
            authenticated,
        },
    })
}

/// `request`'s response at the directory; no response is the failure of step `what`.
async fn send<T: ti_directory_client::http::Transport>(
    transport: &T,
    what: &'static str,
    request: &ti_directory_client::http::Request,
) -> Result<ti_directory_client::http::Response, ti_directory_client::Error> {
    transport
        .send(request)
        .await
        .map_err(|source| ti_directory_client::Error::Transport { what, source })
}

/// The owner token for the directory's API: `login` runs when there is no token, when the
/// one at hand expires within [`RENEW_BEFORE`] seconds, and after the directory refused
/// it.
pub struct OwnerTokens<L, N, R> {
    login: L,
    now: N,
    current: RefCell<Option<Issued<R>>>,
}

impl<L, N, R> OwnerTokens<L, N, R>
where
    L: AsyncFn() -> Result<Issued<R>, OwnerError>,
    N: Fn() -> Timestamp,
    R: Clone,
{
    /// Tokens from `login`, their validity judged at `now`.
    pub fn new(login: L, now: N) -> OwnerTokens<L, N, R> {
        OwnerTokens {
            login,
            now,
            current: RefCell::new(None),
        }
    }

    /// The token in use, after a login when there is none valid for long enough.
    ///
    /// # Errors
    ///
    /// The login's.
    pub async fn issued(&self) -> Result<Issued<R>, OwnerError> {
        if let Some(issued) = self.current.borrow().as_ref()
            && (self.now)().0.saturating_add(RENEW_BEFORE) < issued.expires_at.0
        {
            return Ok(issued.clone());
        }
        let issued = (self.login)().await?;
        *self.current.borrow_mut() = Some(issued.clone());
        Ok(issued)
    }
}

impl<L, N, R> Tokens for OwnerTokens<L, N, R>
where
    L: AsyncFn() -> Result<Issued<R>, OwnerError>,
    N: Fn() -> Timestamp,
    R: Clone,
{
    async fn access_token(&self) -> Result<String, ti_directory_client::Error> {
        match self.issued().await {
            Ok(issued) => Ok(issued.token.access_token),
            Err(OwnerError::Directory(error)) => Err(error),
            Err(OwnerError::Idpd(error)) => Err(ti_directory_client::Error::Token(Box::new(error))),
        }
    }

    async fn refused(&self, token: &str) {
        let mut current = self.current.borrow_mut();
        if current
            .as_ref()
            .is_some_and(|issued| issued.token.access_token == token)
        {
            *current = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use jwz::keys::SoftwareKey;
    use ti_directory_client::http::{Method, Request, Response, TransportError};
    use ti_directory_client::{Error, TokenClaims, tokens};
    use ti_idpd_client::trust::Unverified;

    use super::*;
    use crate::block_on;

    const DIRECTORY: &str = "https://directory.test";
    const IDP: &str = "https://idp.test";

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// Answers the directory's requests in order and records them; the IDP-Dienst is never
    /// to be asked.
    struct Scripted {
        answers: RefCell<VecDeque<Response>>,
        seen: RefCell<Vec<Request>>,
    }

    impl Scripted {
        fn new(answers: Vec<Response>) -> Scripted {
            Scripted {
                answers: RefCell::new(answers.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl ti_directory_client::http::Transport for Scripted {
        async fn send(&self, request: &Request) -> Result<Response, TransportError> {
            self.seen.borrow_mut().push(request.clone());
            self.answers
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| TransportError("the test expected no further request".into()))
        }
    }

    impl ti_idpd_client::http::Transport for Scripted {
        async fn send(
            &self,
            request: &ti_idpd_client::http::Request,
        ) -> Result<ti_idpd_client::http::Response, ti_idpd_client::http::TransportError> {
            Err(ti_idpd_client::http::TransportError(format!(
                "the test expected nothing at the IDP-Dienst: {}",
                request.url
            )))
        }
    }

    #[test]
    fn login_stops_at_the_directorys_redirect_when_it_is_not_the_idps() {
        let key = SoftwareKey::generate(
            ti_jwz::brainpool::BP256R1,
            &ti_jwz::brainpool::registry(),
            std::sync::Arc::new(ti_jwz::brainpool::backend(
                jwz::crypto::rustcrypto::RustCrypto::new(),
            )),
        )
        .unwrap();
        let identity = Identity {
            signer: &key,
            certificate_der: &[0x30, 0x00],
        };
        let directory = Directory::new(DIRECTORY, IDP);
        let now = || Timestamp(1_760_000_000);
        let transport = Scripted::new(vec![response(
            302,
            &[("Location", "https://idp.evil.test/auth?client_id=opaque")],
            "",
        )]);
        let error =
            block_on(login(&transport, &directory, &identity, now, &Unverified)).unwrap_err();
        assert!(
            matches!(
                error,
                OwnerError::Directory(Error::Malformed {
                    what: "owner-authenticate",
                    ..
                })
            ),
            "{error:?}"
        );
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 1, "nothing goes to the foreign IDP");
        assert_eq!(seen[0].url, "https://directory.test/owner-authenticate");
        assert_eq!(seen[0].method, Method::Get);

        let transport = Scripted::new(vec![response(401, &[], r#"{"message":"nope"}"#)]);
        let error =
            block_on(login(&transport, &directory, &identity, now, &Unverified)).unwrap_err();
        assert!(
            matches!(error, OwnerError::Directory(Error::Directory(_))),
            "{error:?}"
        );
    }

    #[test]
    fn the_directorys_idp_is_the_environments_idp_dienst() {
        use ti_types::Env;
        for env in [Env::Prod, Env::Test, Env::Ref, Env::Dev] {
            assert_eq!(
                Directory::for_env(env).idp_url(),
                Idp::for_env(env).base_url(),
                "{env}"
            );
        }
    }

    /// A login that counts itself and issues `token-1`, `token-2`, … valid for 300 s from
    /// `now`.
    fn counting<'a>(
        logins: &'a Cell<u32>,
        now: &'a Cell<u64>,
    ) -> impl AsyncFn() -> Result<Issued<()>, OwnerError> + 'a {
        async move || {
            logins.set(logins.get() + 1);
            Ok(Issued {
                token: AccessToken {
                    access_token: format!("token-{}", logins.get()),
                    token_type: "Bearer".to_owned(),
                    expires_in: 300,
                    claims: TokenClaims::default(),
                },
                expires_at: Timestamp(now.get() + 300),
                how: (),
            })
        }
    }

    #[test]
    fn the_owner_token_is_renewed_before_it_expires() {
        let logins = Cell::new(0);
        let now = Cell::new(1_760_000_000);
        let tokens = OwnerTokens::new(counting(&logins, &now), || Timestamp(now.get()));
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-1");
        now.set(now.get() + 300 - RENEW_BEFORE - 1);
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-1");
        assert_eq!(logins.get(), 1, "a token valid long enough is kept");
        now.set(now.get() + 1);
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-2");
        assert_eq!(logins.get(), 2);
    }

    #[test]
    fn a_refused_owner_token_is_not_handed_out_again() {
        let logins = Cell::new(0);
        let now = Cell::new(1_760_000_000);
        let tokens = OwnerTokens::new(counting(&logins, &now), || Timestamp(now.get()));
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-1");
        block_on(tokens.refused("another"));
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-1");
        block_on(tokens.refused("token-1"));
        assert_eq!(block_on(tokens.access_token()).unwrap(), "token-2");

        // Through the directory: a 401 costs one login more and one retry.
        let transport = Scripted::new(vec![response(401, &[], ""), response(200, &[], "{}")]);
        let request = ti_directory_client::http::Request {
            method: Method::Get,
            url: format!("{DIRECTORY}/search/Organization"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = block_on(tokens::send(&transport, &tokens, "search", &request)).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(logins.get(), 3);
        let bearers: Vec<_> = transport
            .seen
            .borrow()
            .iter()
            .map(|r| r.headers[0].1.clone())
            .collect();
        assert_eq!(bearers, ["Bearer token-2", "Bearer token-3"]);
    }

    #[test]
    fn a_failed_idp_login_is_the_directorys_token_error() {
        let tokens = OwnerTokens::new(
            async || -> Result<Issued<()>, OwnerError> {
                Err(OwnerError::Idpd(ti_idpd_client::Error::Transport {
                    what: "discovery document",
                    source: ti_idpd_client::http::TransportError("refused".into()),
                }))
            },
            || Timestamp(0),
        );
        let error = block_on(tokens.access_token()).unwrap_err();
        assert!(matches!(error, Error::Token(_)), "{error}");
    }
}
