//! A transport that answers from a script and records what it was asked.

#![allow(dead_code, reason = "each test file uses a part")]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use ti_connector_client::{Method, Request, Response, Transport, TransportError};

/// What a request looked like, owned.
#[derive(Debug)]
pub struct Seen {
    pub method: Method,
    pub url: String,
    pub soap_action: Option<String>,
    pub authorization: Option<String>,
    pub if_none_match: Option<String>,
    pub body: String,
    pub timeout: Duration,
}

/// Answers from a script and records every request.
#[derive(Debug, Default)]
pub struct Scripted {
    answers: RefCell<VecDeque<Result<Response, TransportError>>>,
    pub seen: RefCell<Vec<Seen>>,
}

impl Scripted {
    pub fn new(responses: impl IntoIterator<Item = Response>) -> Self {
        Scripted {
            answers: RefCell::new(responses.into_iter().map(Ok).collect()),
            seen: RefCell::default(),
        }
    }

    pub fn failing(error: TransportError) -> Self {
        Scripted {
            answers: RefCell::new([Err(error)].into()),
            seen: RefCell::default(),
        }
    }
}

impl Transport for Scripted {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        self.seen.borrow_mut().push(Seen {
            method: request.method,
            url: request.url.to_owned(),
            soap_action: request.soap_action.map(str::to_owned),
            authorization: request.authorization.map(str::to_owned),
            if_none_match: request.if_none_match.map(str::to_owned),
            body: String::from_utf8(request.body.to_vec()).unwrap(),
            timeout: request.timeout,
        });
        self.answers
            .borrow_mut()
            .pop_front()
            .expect("the script has an answer for every request")
    }
}

pub fn ok(status: u16, body: &str) -> Response {
    Response {
        status,
        body: body.as_bytes().to_vec(),
        ..Response::default()
    }
}
