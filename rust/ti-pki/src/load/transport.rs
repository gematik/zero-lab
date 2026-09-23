//! Getting bytes from somewhere. A transport owns everything about the connection:
//! proxy, timeouts, TLS, retries, user agent. `ti-pki` only supplies the URL and the
//! conditional-request validators, or for OCSP the request body.

use core::fmt;

use super::artifact::{ArtifactRequest, ArtifactResponse};

/// An HTTP POST, as OCSP sends it (RFC 6960 appendix A.1).
#[derive(Clone, Copy, Debug)]
pub struct PostRequest<'a> {
    /// The URL; OCSP responders in the TI are plain `http://`.
    pub url: &'a str,
    /// The `Content-Type` of the body, e.g. `application/ocsp-request`.
    pub content_type: &'a str,
    /// The `Accept` header, e.g. `application/ocsp-response`.
    pub accept: &'a str,
    /// The request body.
    pub body: &'a [u8],
}

/// Fetches artefacts and posts OCSP requests.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Transport {
    /// Performs `req`. Answers [`ArtifactResponse::NotModified`] only when the request
    /// carried a validator that still matches.
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError>;

    /// Performs `req` and returns the body of a 2xx response; any other status is a
    /// [`TransportErrorKind::Status`] error. A transport that cannot post (files, say)
    /// answers [`TransportErrorKind::Other`].
    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        (**self).get(req).await
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        (**self).post(req).await
    }
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        (**self).get(req).await
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        (**self).post(req).await
    }
}

/// What kind of failure a transport hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// Connection, DNS, TLS or timeout.
    Network,
    /// A response with this status other than 2xx or 304.
    Status(u16),
    /// Local I/O, e.g. a file that cannot be read.
    Io,
    /// Anything else.
    Other,
}

/// A transport failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct TransportError {
    /// The kind of failure.
    pub kind: TransportErrorKind,
    /// Human-readable detail.
    pub message: String,
    /// Whether trying again later may succeed.
    pub retryable: bool,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportErrorKind::Network => f.write_str("network error"),
            TransportErrorKind::Status(code) => write!(f, "HTTP status {code}"),
            TransportErrorKind::Io => f.write_str("I/O error"),
            TransportErrorKind::Other => f.write_str("transport error"),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
type Script<T> = std::sync::Mutex<std::collections::VecDeque<Result<T, TransportError>>>;

/// A transport that plays back scripted responses in order and records the requests it
/// saw; for tests. GETs and POSTs have separate scripts.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct MockTransport {
    script: Script<ArtifactResponse>,
    posts: Script<Vec<u8>>,
    seen: std::sync::Mutex<Vec<MockRequest>>,
    posted: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

/// A request as [`MockTransport`] recorded it.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockRequest {
    /// Which artefact.
    pub artifact: super::artifact::Artifact,
    /// The URL.
    pub url: String,
    /// The `If-None-Match` validator.
    pub etag: Option<String>,
}

#[cfg(any(test, feature = "test-util"))]
impl MockTransport {
    /// A transport that answers with `script`, one entry per call.
    pub fn new(script: impl IntoIterator<Item = Result<ArtifactResponse, TransportError>>) -> Self {
        MockTransport {
            script: std::sync::Mutex::new(script.into_iter().collect()),
            ..MockTransport::default()
        }
    }

    /// A transport that answers POSTs with `script`, one entry per call.
    pub fn posting(script: impl IntoIterator<Item = Result<Vec<u8>, TransportError>>) -> Self {
        MockTransport {
            posts: std::sync::Mutex::new(script.into_iter().collect()),
            ..MockTransport::default()
        }
    }

    /// The URL and body of every POST received so far.
    ///
    /// # Panics
    ///
    /// If a previous call panicked while holding the lock.
    pub fn posts(&self) -> Vec<(String, Vec<u8>)> {
        self.posted.lock().unwrap().clone()
    }

    /// The requests received so far.
    ///
    /// # Panics
    ///
    /// If a previous call panicked while holding the lock.
    pub fn requests(&self) -> Vec<MockRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Transport for MockTransport {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        self.seen.lock().unwrap().push(MockRequest {
            artifact: req.artifact,
            url: req.url.to_owned(),
            etag: req.etag.map(str::to_owned),
        });
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(exhausted()))
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        self.posted
            .lock()
            .unwrap()
            .push((req.url.to_owned(), req.body.to_vec()));
        self.posts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(exhausted()))
    }
}

#[cfg(any(test, feature = "test-util"))]
fn exhausted() -> TransportError {
    TransportError {
        kind: TransportErrorKind::Other,
        message: "mock script exhausted".into(),
        retryable: false,
    }
}
