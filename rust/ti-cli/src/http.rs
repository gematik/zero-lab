//! The HTTP client behind downloads and OCSP: blocking ureq on rustls with ring, the
//! operating system's trust store, and the curl-like options of [`NetArgs`] applied the
//! way curl applies them.
//!
//! Blocking is deliberate: a command makes a handful of sequential requests, so an async
//! runtime would add a large dependency tree for nothing. ti-pki's transport futures
//! therefore complete on their first poll (see [`crate::block`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ti_pki::load::{
    ArtifactRequest, ArtifactResponse, PostRequest, ResponseMeta, Source, Transport,
    TransportError, TransportErrorKind,
};
use ureq::Agent;
use ureq::http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    LAST_MODIFIED,
};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, TlsProvider};

use crate::error::CliError;
use crate::net::{NetArgs, redact};
use crate::output::diagnostic;

/// curl's retry back-off: one second, doubling, capped at ten minutes.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_mins(10);

/// Largest body read; the production TSL is under 1 MiB.
const MAX_BODY: u64 = 32 * 1024 * 1024;

/// The transport for downloads and OCSP.
pub fn transport(net: &NetArgs, verbose: u8) -> Result<Http, CliError> {
    let tls = tls_config(net)?;
    let agent = |scheme| -> Result<Agent, CliError> {
        Ok(Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(net.connect_timeout))
            .timeout_global(Some(net.max_time))
            .user_agent(net.user_agent())
            .tls_config(tls.clone())
            .proxy(proxy(net, scheme)?)
            .build()
            .new_agent())
    };
    Ok(Http {
        tls: agent("https")?,
        plain: agent("http")?,
        retries: net.retry,
        verbose,
    })
}

fn tls_config(net: &NetArgs) -> Result<TlsConfig, CliError> {
    let (files, dir) = net.ca_sources();
    let roots = if net.insecure || (files.is_empty() && dir.is_none()) {
        RootCerts::PlatformVerifier
    } else {
        let mut certs = Vec::new();
        for path in files.iter().chain(ca_dir_files(dir.as_deref())?.iter()) {
            certs.extend(pem_certificates(path)?);
        }
        // Like curl: a CA option replaces the system store rather than adding to it.
        RootCerts::new_with_certs(&certs)
    };
    Ok(TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(roots)
        .disable_verification(net.insecure)
        .build())
}

fn pem_certificates(path: &Path) -> Result<Vec<Certificate<'static>>, CliError> {
    let setup = |e: &dyn std::fmt::Display| CliError::HttpSetup(format!("{}: {e}", path.display()));
    let pem = std::fs::read(path).map_err(|e| setup(&e))?;
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        if let PemItem::Certificate(cert) = item.map_err(|e| setup(&e))? {
            certs.push(cert);
        }
    }
    if certs.is_empty() {
        return Err(setup(&"no PEM certificate"));
    }
    Ok(certs)
}

/// The proxy for URLs of `scheme`, as curl picks it: `-x`, else `<scheme>_proxy`, else
/// `ALL_PROXY`, each variable lower case first; `--noproxy`, else `NO_PROXY`, exempts
/// hosts. `-x ""` or a no-proxy list of `*` turns proxies off.
fn proxy(net: &NetArgs, scheme: &str) -> Result<Option<ureq::Proxy>, CliError> {
    let env = |name: &str| {
        [name.to_ascii_lowercase(), name.to_ascii_uppercase()]
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
    };
    let url = match net.proxy.as_deref() {
        Some("") => return Ok(None),
        Some(url) => url.to_owned(),
        None => match env(&format!("{scheme}_proxy")).or_else(|| env("all_proxy")) {
            Some(url) => url,
            None => return Ok(None),
        },
    };
    let except = net.noproxy.clone().or_else(|| env("no_proxy"));
    let entries: Vec<&str> = except
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.contains(&"*") {
        return Ok(None);
    }
    let invalid = |_| CliError::HttpSetup(format!("proxy {:?} is not a valid URL", redact(&url)));
    let parsed = ureq::Proxy::new(&url).map_err(invalid)?;
    let mut builder = ureq::Proxy::builder(parsed.protocol())
        .host(parsed.host())
        .port(parsed.port());
    if let Some(user) = parsed.username() {
        builder = builder.username(user);
    }
    if let Some(password) = parsed.password() {
        builder = builder.password(password);
    }
    for entry in entries {
        // curl exempts a domain's subdomains too; ureq matches `example.com` literally
        // and `.example.com` below it, so both are added.
        let domain = entry.trim_start_matches("*.").trim_start_matches('.');
        builder = builder.no_proxy(domain).no_proxy(&format!(".{domain}"));
    }
    builder.build().map(Some).map_err(invalid)
}

/// The certificate files of a `--capath` directory: `*.pem`, `*.crt` and OpenSSL's
/// hashed names (`<hash>.0`).
fn ca_dir_files(dir: Option<&Path>) -> Result<Vec<PathBuf>, CliError> {
    let Some(dir) = dir else {
        return Ok(Vec::new());
    };
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CliError::HttpSetup(format!("{}: {e}", dir.display())))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path.extension().is_some_and(|ext| {
                    ext == "pem" || ext == "crt" || ext.to_str().is_some_and(is_hash_suffix)
                })
        })
        .collect();
    files.sort();
    Ok(files)
}

fn is_hash_suffix(ext: &str) -> bool {
    !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_digit())
}

/// ti-pki's transport over ureq, with curl's `--retry` and a `-v` line per request.
/// One agent per scheme, since curl proxies `http://` and `https://` separately.
pub struct Http {
    tls: Agent,
    plain: Agent,
    retries: u32,
    verbose: u8,
}

impl Http {
    fn agent(&self, url: &str) -> &Agent {
        if url.starts_with("http://") {
            &self.plain
        } else {
            &self.tls
        }
    }

    fn retrying<T>(
        &self,
        what: &str,
        attempt: impl Fn() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let mut delay = FIRST_RETRY_DELAY;
        let mut left = self.retries;
        loop {
            match attempt() {
                Err(error) if error.retryable && left > 0 => {
                    self.log(format_args!("{what}: {error}; retrying in {delay:?}"));
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(MAX_RETRY_DELAY);
                    left -= 1;
                }
                Err(error) => {
                    self.log(format_args!("{what}: {error}"));
                    return Err(error);
                }
                ok => return ok,
            }
        }
    }

    fn log(&self, message: impl std::fmt::Display) {
        if self.verbose >= 1 {
            diagnostic(message);
        }
    }

    fn get_once(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        let mut request = self.agent(req.url).get(req.url);
        if let Some(etag) = req.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(modified) = req.last_modified {
            request = request.header(IF_MODIFIED_SINCE, modified);
        }
        let mut response = request.call().map_err(|e| network(&e, req.url))?;
        let meta = response_meta(response.headers());
        match response.status().as_u16() {
            304 if req.etag.is_some() || req.last_modified.is_some() => {
                Ok(ArtifactResponse::NotModified { meta })
            }
            200..=299 => {
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_BODY)
                    .read_to_vec()
                    .map_err(|e| network(&e, req.url))?;
                Ok(ArtifactResponse::Fresh { body, meta })
            }
            status => Err(status_error(status, req.url)),
        }
    }

    fn post_once(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        let mut response = self
            .agent(req.url)
            .post(req.url)
            .header(CONTENT_TYPE, req.content_type)
            .header(ACCEPT, req.accept)
            .send(req.body)
            .map_err(|e| network(&e, req.url))?;
        let status = response.status().as_u16();
        if !(200..=299).contains(&status) {
            return Err(status_error(status, req.url));
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| network(&e, req.url))
    }
}

impl Transport for Http {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        let what = format!("GET {}", req.url);
        let response = self.retrying(&what, || self.get_once(req))?;
        match &response {
            ArtifactResponse::Fresh { body, .. } => {
                self.log(format_args!("{what}: {} bytes", body.len()));
            }
            ArtifactResponse::NotModified { .. } => self.log(format_args!("{what}: not modified")),
        }
        Ok(response)
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        let what = format!("POST {}", req.url);
        let body = self.retrying(&what, || self.post_once(req))?;
        self.log(format_args!("{what}: {} bytes", body.len()));
        Ok(body)
    }
}

fn status_error(status: u16, url: &str) -> TransportError {
    TransportError {
        kind: TransportErrorKind::Status(status),
        message: format!("HTTP {status} from {url}"),
        retryable: status >= 500 || status == 429,
    }
}

/// A failure before a status arrived, with the URL and the causes. TLS and proxy
/// configuration errors do not go away by retrying.
fn network(error: &ureq::Error, url: &str) -> TransportError {
    let mut message = format!("{url}: {error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let text = cause.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = cause.source();
    }
    let retryable = !matches!(
        error,
        ureq::Error::Tls(_) | ureq::Error::InvalidProxyUrl | ureq::Error::BadUri(_)
    );
    TransportError {
        kind: TransportErrorKind::Network,
        message,
        retryable,
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

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    use clap::Parser;
    use ti_pki::load::Artifact;

    use super::*;

    #[test]
    fn hashed_names_count_as_certificates() {
        assert!(is_hash_suffix("0"));
        assert!(is_hash_suffix("12"));
        assert!(!is_hash_suffix("key"));
        assert!(!is_hash_suffix(""));
    }

    #[test]
    fn cache_control_max_age() {
        assert_eq!(
            max_age("public, max-age=3600"),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(max_age("no-cache"), None);
    }

    /// Serves one scripted HTTP/1.1 response per connection, returning the requests.
    fn serve(responses: Vec<&'static str>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsl.xml", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request = String::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        request.push_str(&line.to_ascii_lowercase());
                    }
                    let length = request
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .map_or(0, |n| n.trim().parse().unwrap());
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    request.push_str(&String::from_utf8_lossy(&body));
                    stream.write_all(response.as_bytes()).unwrap();
                    request
                })
                .collect()
        });
        (url, server)
    }

    #[derive(Parser)]
    struct Args {
        #[command(flatten)]
        net: NetArgs,
    }

    #[test]
    fn conditional_get_and_post() {
        let (url, server) = serve(vec![
            "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=600\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntsl",
            "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nresp",
        ]);
        // No proxy, whatever the environment of the test run says.
        let http = transport(&Args::parse_from([crate::BIN, "-x", ""]).net, 0).unwrap();
        let get = |etag| {
            http.get_once(&ArtifactRequest {
                artifact: Artifact::Tsl,
                url: &url,
                etag,
                last_modified: None,
            })
        };

        let ArtifactResponse::Fresh { body, meta } = get(None).unwrap() else {
            panic!("expected a body")
        };
        assert_eq!(body, b"tsl");
        assert_eq!(meta.etag.as_deref(), Some("\"v1\""));
        assert_eq!(meta.max_age, Some(Duration::from_secs(600)));
        assert!(matches!(
            get(Some("\"v1\"")).unwrap(),
            ArtifactResponse::NotModified { .. }
        ));
        let error = get(None).unwrap_err();
        assert_eq!(error.kind, TransportErrorKind::Status(503));
        assert!(error.retryable);
        let posted = http
            .post_once(&PostRequest {
                url: &url,
                content_type: "application/ocsp-request",
                accept: "application/ocsp-response",
                body: b"req",
            })
            .unwrap();
        assert_eq!(posted, b"resp");

        let requests = server.join().unwrap();
        assert!(requests[1].contains("if-none-match: \"v1\""));
        assert!(requests[3].starts_with("post "));
        assert!(requests[3].contains("content-type: application/ocsp-request"));
        assert!(requests[3].ends_with("req"));
    }
}
