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

//! A request to the directory's API with a token the host provides (`tokens::send`): the
//! token goes as bearer, a refused one is reported to the host so it is not handed out
//! again, and the request is retried once.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use ti_directory_client::Error;
use ti_directory_client::http::{Method, Request, Response, Transport, TransportError};
use ti_directory_client::tokens::{self, Tokens};

/// The request awaits only the transport and the tokens, which answer at once here: one
/// poll completes it.
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => {
            panic!("a synchronous transport and token source never leave the request pending")
        }
    }
}

/// Hands out `token-1`, `token-2`, … and records the refused ones.
#[derive(Default)]
struct Counted {
    issued: Cell<u32>,
    refused: RefCell<Vec<String>>,
}

impl Tokens for Counted {
    async fn access_token(&self) -> Result<String, Error> {
        self.issued.set(self.issued.get() + 1);
        Ok(format!("token-{}", self.issued.get()))
    }

    async fn refused(&self, token: &str) {
        self.refused.borrow_mut().push(token.to_owned());
    }
}

/// A host that has no token.
struct Failing;

impl Tokens for Failing {
    async fn access_token(&self) -> Result<String, Error> {
        Err(Error::Token("the login failed".into()))
    }

    async fn refused(&self, _: &str) {
        panic!("no token was handed out");
    }
}

/// Answers in order and records every request.
struct Scripted {
    answers: RefCell<VecDeque<Response>>,
    seen: RefCell<Vec<Request>>,
}

impl Scripted {
    fn new(statuses: &[u16]) -> Scripted {
        Scripted {
            answers: RefCell::new(
                statuses
                    .iter()
                    .map(|&status| Response {
                        status,
                        headers: Vec::new(),
                        body: Vec::new(),
                    })
                    .collect(),
            ),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn bearers(&self) -> Vec<String> {
        self.seen
            .borrow()
            .iter()
            .map(|request| {
                let values: Vec<&str> = request
                    .headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .map(|(_, value)| value.as_str())
                    .collect();
                assert_eq!(values.len(), 1, "one Authorization: {values:?}");
                values[0].to_owned()
            })
            .collect()
    }
}

impl Transport for Scripted {
    async fn send(&self, request: &Request) -> Result<Response, TransportError> {
        self.seen.borrow_mut().push(request.clone());
        self.answers
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| TransportError("the test expected no further request".into()))
    }
}

/// State behind an `Rc`, neither `Send` nor `Sync`, as a browser host over JS fetch holds it.
struct Local<T>(Rc<T>);

impl Transport for Local<Scripted> {
    async fn send(&self, request: &Request) -> Result<Response, TransportError> {
        self.0.send(request).await
    }
}

impl Tokens for Local<Counted> {
    async fn access_token(&self) -> Result<String, Error> {
        self.0.access_token().await
    }

    async fn refused(&self, token: &str) {
        self.0.refused(token).await;
    }
}

fn search() -> Request {
    Request {
        method: Method::Get,
        url: "https://directory.test/search/Organization".to_owned(),
        headers: vec![
            ("accept".to_owned(), "application/fhir+json".to_owned()),
            ("Authorization".to_owned(), "Bearer stale".to_owned()),
        ],
        body: Vec::new(),
    }
}

#[test]
fn rfc_6750_3_1_a_refused_token_is_reported_and_the_request_retried_once() {
    let tokens = Counted::default();
    let transport = Scripted::new(&[401, 200]);
    let response = ready(tokens::send(&transport, &tokens, "search", &search())).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(transport.bearers(), ["Bearer token-1", "Bearer token-2"]);
    assert_eq!(*tokens.refused.borrow(), ["token-1"]);
    assert_eq!(
        transport.seen.borrow()[1].url,
        "https://directory.test/search/Organization"
    );

    // A directory that refuses every token gets one retry, not a loop.
    let tokens = Counted::default();
    let transport = Scripted::new(&[401, 401, 200]);
    let response = ready(tokens::send(&transport, &tokens, "search", &search())).unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(transport.seen.borrow().len(), 2);
    assert_eq!(*tokens.refused.borrow(), ["token-1", "token-2"]);
}

#[test]
fn a_token_the_directory_accepts_is_sent_once_and_kept() {
    for status in [200, 403, 404, 500] {
        let tokens = Counted::default();
        let transport = Scripted::new(&[status, 200]);
        let response = ready(tokens::send(&transport, &tokens, "search", &search())).unwrap();
        assert_eq!(response.status, status);
        assert_eq!(transport.bearers(), ["Bearer token-1"]);
        assert!(tokens.refused.borrow().is_empty(), "{status}");
    }
}

#[test]
fn without_a_token_nothing_is_sent() {
    let transport = Scripted::new(&[200]);
    let error = ready(tokens::send(&transport, &Failing, "search", &search())).unwrap_err();
    assert!(matches!(error, Error::Token(_)), "{error}");
    assert_eq!(
        error.to_string(),
        "FHIR-Directory access token: the login failed"
    );
    assert!(transport.seen.borrow().is_empty());

    let error = ready(tokens::send(
        &Scripted::new(&[]),
        &Counted::default(),
        "search",
        &search(),
    ))
    .unwrap_err();
    assert!(
        matches!(error, Error::Transport { what: "search", .. }),
        "{error}"
    );
}

/// The traits carry no `Send` bound so that a browser host can implement them; nothing on
/// the way from the request to the retry may ask for one.
#[test]
fn a_transport_and_tokens_that_are_not_send_drive_a_directory_request() {
    let tokens = Local(Rc::new(Counted::default()));
    let transport = Local(Rc::new(Scripted::new(&[401, 200])));
    let response = ready(tokens::send(&transport, &tokens, "search", &search())).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(transport.0.bearers(), ["Bearer token-1", "Bearer token-2"]);
    assert_eq!(*tokens.0.refused.borrow(), ["token-1"]);
}
