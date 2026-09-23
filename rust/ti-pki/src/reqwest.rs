//! [`crate::load::Transport`] over a caller-provided [`reqwest::Client`],
//! native and wasm32 (browser `fetch`).
//!
//! The client is the caller's: proxy, timeouts, TLS roots and user agent are configured
//! there. `ti-pki` depends on reqwest without default features, so TLS comes from the
//! application's own reqwest dependency (e.g. `features = ["rustls"]`); Cargo unifies
//! the two.
//!
//! ```no_run
//! # async fn demo() -> Result<(), ti_pki::Error> {
//! use ti_pki::load::{HttpLoader, Loader, SystemClock};
//! use ti_pki::reqwest::ReqwestTransport;
//!
//! let config = ti_pki::TrustConfig::preset_prod();
//! let transport = ReqwestTransport::new(reqwest::Client::new());
//! let loader = HttpLoader::new(&config, transport, SystemClock);
//! let material = loader.load_all().await;
//! # Ok(()) }
//! ```

use core::time::Duration;

use ::reqwest::header::{
    CACHE_CONTROL, ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use ::reqwest::{Client, StatusCode};

use crate::load::{
    ArtifactRequest, ArtifactResponse, ResponseMeta, Source, Transport, TransportError,
    TransportErrorKind,
};

/// Fetches artefacts with a [`reqwest::Client`], sending `If-None-Match` and
/// `If-Modified-Since` and mapping `304` to [`ArtifactResponse::NotModified`].
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: Client,
}

impl ReqwestTransport {
    /// A transport using `client` for every request.
    pub fn new(client: Client) -> Self {
        ReqwestTransport { client }
    }
}

impl Transport for ReqwestTransport {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        let mut request = self.client.get(req.url);
        if let Some(etag) = req.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = req.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
        let response = request.send().await.map_err(|e| network(&e))?;
        let status = response.status();
        let meta = response_meta(response.headers());
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ArtifactResponse::NotModified { meta });
        }
        if !status.is_success() {
            return Err(TransportError {
                kind: TransportErrorKind::Status(status.as_u16()),
                message: format!("{} from {}", status, req.url),
                retryable: status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
            });
        }
        let body = response.bytes().await.map_err(|e| network(&e))?.to_vec();
        Ok(ArtifactResponse::Fresh { body, meta })
    }
}

fn network(error: &::reqwest::Error) -> TransportError {
    TransportError {
        kind: TransportErrorKind::Network,
        message: error.to_string(),
        retryable: true,
    }
}

fn response_meta(headers: &HeaderMap) -> ResponseMeta {
    let text = |name| headers.get(name).and_then(|v| v.to_str().ok());
    ResponseMeta {
        etag: text(ETAG).map(str::to_owned),
        last_modified: text(LAST_MODIFIED).map(str::to_owned),
        max_age: text(CACHE_CONTROL).and_then(max_age),
        source: Source::Http,
    }
}

/// The `max-age` directive of a `Cache-Control` value.
fn max_age(cache_control: &str) -> Option<Duration> {
    cache_control.split(',').find_map(|directive| {
        let (name, value) = directive.trim().split_once('=')?;
        name.eq_ignore_ascii_case("max-age")
            .then(|| value.trim_matches('"').parse().ok())
            .flatten()
            .map(Duration::from_secs)
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use super::*;
    use crate::load::Artifact;

    #[test]
    fn cache_control_max_age() {
        assert_eq!(
            max_age("public, max-age=3600"),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(max_age("Max-Age=\"60\""), Some(Duration::from_secs(60)));
        assert_eq!(max_age("no-cache"), None);
        assert_eq!(max_age("max-age=soon"), None);
    }

    /// Serves one HTTP/1.1 response per scripted entry, returning the request headers.
    fn serve(responses: Vec<&'static str>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsl.xml", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        request.push_str(&line.to_ascii_lowercase());
                    }
                    stream.write_all(response.as_bytes()).unwrap();
                    request
                })
                .collect()
        });
        (url, server)
    }

    #[test]
    fn conditional_round_trip() {
        let (url, server) = serve(vec![
            "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=600\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntsl",
            "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let transport = ReqwestTransport::new(Client::new());
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let request = |etag| ArtifactRequest {
            artifact: Artifact::Tsl,
            url: &url,
            etag,
            last_modified: None,
        };

        let fresh = runtime.block_on(transport.get(&request(None))).unwrap();
        let ArtifactResponse::Fresh { body, meta } = fresh else {
            panic!("expected a body")
        };
        assert_eq!(body, b"tsl");
        assert_eq!(meta.etag.as_deref(), Some("\"v1\""));
        assert_eq!(meta.max_age, Some(Duration::from_secs(600)));

        let revalidated = runtime
            .block_on(transport.get(&request(Some("\"v1\""))))
            .unwrap();
        assert!(matches!(revalidated, ArtifactResponse::NotModified { .. }));

        let error = runtime.block_on(transport.get(&request(None))).unwrap_err();
        assert_eq!(error.kind, TransportErrorKind::Status(503));
        assert!(error.retryable);

        let requests = server.join().unwrap();
        assert!(requests[1].contains("if-none-match: \"v1\""));
    }
}
