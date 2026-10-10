//! The HTTP the flow needs, as data: a request to perform and the response it got. A
//! [`Transport`] performs them without following redirects, because a `302` is an
//! answer here (the code, or the IDP's error).

use core::fmt;

/// `GET` or `POST`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Method::Get => "GET",
            Method::Post => "POST",
        })
    }
}

/// A request to perform. Redirects must not be followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The absolute URL.
    pub url: String,
    /// Headers to send, besides what the client adds (`Host`, `User-Agent`,
    /// `Content-Length`).
    pub headers: Vec<(String, String)>,
    /// The body; empty for `GET`.
    pub body: Vec<u8>,
}

impl Request {
    pub(crate) fn get(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn post_form(url: &str, body: String) -> Request {
        Request {
            method: Method::Post,
            url: url.to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: body.into_bytes(),
        }
    }
}

/// What came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers, names as received.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header named `name`, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Performs requests. Implementations must not follow redirects and must return
/// non-2xx responses as responses, not errors.
pub trait Transport {
    /// Performs `request`.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when no response was obtained (DNS, connection, TLS, timeout).
    fn send(&self, request: &Request) -> Result<Response, TransportError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        (**self).send(request)
    }
}

/// No response: what the client said.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);
