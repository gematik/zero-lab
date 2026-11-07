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

//! What a front end sees of the requests to the Konnektor, the IDP-Dienst and the
//! FHIR-Directory: the [`Watcher`] of a [`Client`](crate::Client) is called before each
//! request and once its answer or failure is in, so that a front end can show them
//! (`ti -v`) without wrapping the transports. Never the `Authorization` header or another
//! credential; a Konnektor body with its comfort user ID masked.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ti_directory_client::http as directory;
use ti_idpd_client::http as idpd;

/// Told about every request of the transports a [`Client`](crate::Client) makes, on the
/// requesting thread.
pub type Watcher = Arc<dyn Fn(&Exchange<'_>) + Send + Sync>;

/// The service a request goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The Konnektor: its service directory and SOAP calls.
    Konnektor,
    /// The IDP-Dienst.
    IdpDienst,
    /// The FHIR-Directory and its Keycloak.
    Directory,
}

/// A SOAP operation of a Konnektor call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operation {
    /// The service, e.g. `SignatureService`.
    pub service: &'static str,
    /// The service's version, e.g. `7.5`.
    pub version: &'static str,
    /// The operation, e.g. `SignDocument`.
    pub name: &'static str,
}

/// A request as a watcher sees it.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Where it goes.
    pub service: Service,
    /// `GET` or `POST`.
    pub method: &'static str,
    /// The SOAP operation of a Konnektor call.
    pub operation: Option<Operation>,
    /// The URL.
    pub url: &'a str,
    body: Body<'a>,
}

#[derive(Clone, Copy, Debug)]
enum Body<'a> {
    Plain(&'a [u8]),
    Konnektor(&'a ti_connector_client::Request<'a>),
}

impl<'a> Request<'a> {
    /// The body as it may be shown: a Konnektor's with its comfort user ID masked
    /// ([`ti_connector_client::Request::redacted_body`]).
    pub fn body(&self) -> Cow<'a, [u8]> {
        match self.body {
            Body::Plain(body) => Cow::Borrowed(body),
            Body::Konnektor(request) => Cow::Owned(request.redacted_body()),
        }
    }

    /// Whether the request has a body.
    pub fn has_body(&self) -> bool {
        match self.body {
            Body::Plain(body) => !body.is_empty(),
            Body::Konnektor(request) => !request.body.is_empty(),
        }
    }
}

/// An answer, whatever its status.
#[derive(Clone, Copy, Debug)]
pub struct Answer<'a> {
    /// The HTTP status.
    pub status: u16,
    /// The body.
    pub body: &'a [u8],
}

/// One step of a request.
#[derive(Clone, Copy, Debug)]
pub enum Exchange<'a> {
    /// About to be sent.
    Sending(&'a Request<'a>),
    /// Answered, or failed without an answer.
    Done {
        /// The request.
        request: &'a Request<'a>,
        /// The answer, or why there is none.
        answer: Result<Answer<'a>, &'a str>,
        /// From sending to the answer.
        took: Duration,
    },
}

/// A transport whose requests a [`Watcher`] sees; without one it only forwards. The
/// transports a [`Client`](crate::Client) makes come in it.
#[derive(Clone)]
pub struct Watched<T> {
    inner: T,
    watcher: Option<Watcher>,
}

impl<T> std::fmt::Debug for Watched<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watched")
            .field("watched", &self.watcher.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> Watched<T> {
    /// `inner`, its requests told to `watcher`.
    pub fn new(inner: T, watcher: Option<Watcher>) -> Watched<T> {
        Watched { inner, watcher }
    }

    async fn watch<R, E>(
        &self,
        request: &Request<'_>,
        send: impl Future<Output = Result<R, E>>,
        answer: impl Fn(&R) -> Answer<'_>,
        failure: impl Fn(&E) -> &str,
    ) -> Result<R, E> {
        let Some(watcher) = &self.watcher else {
            return send.await;
        };
        watcher(&Exchange::Sending(request));
        let start = Instant::now();
        let result = send.await;
        let took = start.elapsed();
        watcher(&Exchange::Done {
            request,
            answer: result.as_ref().map(&answer).map_err(&failure),
            took,
        });
        result
    }
}

impl<T: ti_connector_client::Transport> ti_connector_client::Transport for Watched<T> {
    async fn send(
        &self,
        request: &ti_connector_client::Request<'_>,
    ) -> Result<ti_connector_client::Response, ti_connector_client::TransportError> {
        let watched = Request {
            service: Service::Konnektor,
            method: match request.method {
                ti_connector_client::Method::Get => "GET",
                ti_connector_client::Method::Post => "POST",
            },
            operation: request.operation.map(|op| Operation {
                service: op.service,
                version: op.version,
                name: op.name,
            }),
            url: request.url,
            body: Body::Konnektor(request),
        };
        self.watch(
            &watched,
            self.inner.send(request),
            |response| Answer {
                status: response.status,
                body: &response.body,
            },
            |error| error.message.as_str(),
        )
        .await
    }
}

impl<T: idpd::Transport> idpd::Transport for Watched<T> {
    async fn send(&self, request: &idpd::Request) -> Result<idpd::Response, idpd::TransportError> {
        let watched = Request {
            service: Service::IdpDienst,
            method: match request.method {
                idpd::Method::Get => "GET",
                idpd::Method::Post => "POST",
            },
            operation: None,
            url: &request.url,
            body: Body::Plain(&request.body),
        };
        self.watch(
            &watched,
            self.inner.send(request),
            |response| Answer {
                status: response.status,
                body: &response.body,
            },
            |error| error.0.as_str(),
        )
        .await
    }
}

impl<T: directory::Transport> directory::Transport for Watched<T> {
    async fn send(
        &self,
        request: &directory::Request,
    ) -> Result<directory::Response, directory::TransportError> {
        let watched = Request {
            service: Service::Directory,
            method: match request.method {
                directory::Method::Get => "GET",
                directory::Method::Post => "POST",
            },
            operation: None,
            url: &request.url,
            body: Body::Plain(&request.body),
        };
        self.watch(
            &watched,
            self.inner.send(request),
            |response| Answer {
                status: response.status,
                body: &response.body,
            },
            |error| error.0.as_str(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ti_connector_client::Transport as _;

    use super::*;
    use crate::block_on;

    struct Answering;

    impl ti_connector_client::Transport for Answering {
        async fn send(
            &self,
            _: &ti_connector_client::Request<'_>,
        ) -> Result<ti_connector_client::Response, ti_connector_client::TransportError> {
            Ok(ti_connector_client::Response {
                status: 200,
                body: b"ok".to_vec(),
                ..Default::default()
            })
        }
    }

    #[test]
    fn a_watcher_sees_a_konnektor_call_without_its_user_id() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let watcher: Watcher = Arc::new(move |exchange: &Exchange<'_>| {
            let line = match exchange {
                Exchange::Sending(request) => format!(
                    "sending {} {}",
                    request.method,
                    String::from_utf8_lossy(&request.body())
                ),
                Exchange::Done { answer, .. } => format!("done {:?}", answer.map(|a| a.status)),
            };
            log.lock().unwrap().push(line);
        });
        let body = b"<UserId>secret</UserId>";
        let request = ti_connector_client::Request {
            method: ti_connector_client::Method::Post,
            url: "https://konnektor.test/ws/EventService",
            soap_action: None,
            authorization: Some("Basic c2VjcmV0"),
            if_none_match: None,
            if_modified_since: None,
            body,
            timeout: Duration::from_secs(1),
            operation: None,
        };
        let response = block_on(Watched::new(Answering, Some(watcher)).send(&request)).unwrap();
        assert_eq!(response.body, b"ok");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "sending POST <UserId>***</UserId>".to_owned(),
                "done Ok(200)".to_owned()
            ]
        );
    }
}
