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

//! The HTTP client behind downloads, OCSP and the IDP-Dienst: blocking ureq on rustls with
//! ring, every https server verified under the `web` profile of `spec/pki-validation`
//! (ti-tls) against the operating system's roots, and the curl-like options of [`NetArgs`]
//! applied the way curl applies them. ti's endpoints, the TSL download points, the IDP-Dienst
//! and the FHIR-Directory, all present public certificates.
//!
//! Blocking is deliberate: a command makes a handful of sequential requests, so an async
//! runtime would add a large dependency tree for nothing. ti-pki's transport futures
//! therefore complete on their first poll (see [`crate::block`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use ti_pki::load::{
    ArtifactRequest, ArtifactResponse, PostRequest, ResponseMeta, Source, Transport,
    TransportError, TransportErrorKind,
};
use ti_tls::ureq::UreqFetch;
use ti_tls::{WebCheck, WebVerifier};
use ureq::Agent;
use ureq::config::ConfigBuilder;
use ureq::http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    LAST_MODIFIED,
};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, TlsProvider};
use ureq::typestate::AgentScope;

use crate::error::CliError;
use crate::net::{NetArgs, redact};
use crate::output::{Output, diagnostic};

/// curl's retry back-off: one second, doubling, capped at ten minutes.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_mins(10);

/// Largest body read; the production TSL is under 1 MiB.
const MAX_BODY: u64 = 32 * 1024 * 1024;

/// curl's settings for requests to `scheme` URLs: proxy, timeouts, user agent.
pub(crate) fn builder(net: &NetArgs, scheme: &str) -> Result<ConfigBuilder<AgentScope>, CliError> {
    Ok(Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(net.connect_timeout))
        .timeout_global(Some(net.max_time))
        .user_agent(net.user_agent())
        .proxy(proxy(net, scheme)?))
}

/// The agent for plain HTTP: OCSP responders and CRL hosts.
fn plain_agent(net: &NetArgs) -> Result<Agent, CliError> {
    Ok(builder(net, "http")?.build().new_agent())
}

/// The rustls configuration of the `web` profile: `--cacert`/`--capath` as the roots in
/// place of the system's, as curl and Go read `SSL_CERT_FILE`, and every other rule of the
/// profile regardless.
pub(crate) fn web_config(net: &NetArgs) -> Result<Arc<rustls::ClientConfig>, CliError> {
    let (files, dir) = net.ca_sources();
    let check = if files.is_empty() && dir.is_none() {
        WebCheck::system()
    } else {
        let mut roots = Vec::new();
        for path in files.iter().chain(ca_dir_files(dir.as_deref())?.iter()) {
            roots.extend(
                pem_certificates(path)?
                    .iter()
                    .map(|cert| CertificateDer::from(cert.der().to_vec())),
            );
        }
        WebCheck::new(roots)
    };
    let verifier = WebVerifier::new(check, UreqFetch::new(plain_agent(net)?));
    Ok(Arc::new(ti_tls::client_config(Arc::new(verifier))))
}

/// The transport for downloads and OCSP. `-k` skips the TLS check for downloads only: the
/// TSL and roots.json are verified by their content, and the report says so.
pub fn transport(net: &NetArgs, verbose: u8) -> Result<Http, CliError> {
    let tls = if net.insecure {
        builder(net, "https")?
            .tls_config(insecure_tls())
            .build()
            .new_agent()
    } else {
        ti_tls::ureq::agent(builder(net, "https")?, web_config(net)?)
    };
    Ok(Http {
        tls,
        plain: plain_agent(net)?,
        retries: net.retry,
        verbose,
    })
}

/// The agent for the IDP-Dienst flow: proxy, timeouts and user agent as for downloads, the
/// server always verified under `web` (`-k` does not reach it), redirects not followed and no
/// status an error: a `302` is the flow's answer.
pub fn idp_agent(net: &NetArgs) -> Result<Agent, CliError> {
    Ok(ti_tls::ureq::agent(
        builder(net, "https")?.max_redirects(0),
        web_config(net)?,
    ))
}

/// The IDP agent as a [`ti_idpd::http::Transport`] with one `-v` line per request.
pub struct Logged<'a> {
    inner: ti_idpd::ureq::UreqTransport,
    out: &'a Output,
}

impl<'a> Logged<'a> {
    /// The transport over [`idp_agent`].
    pub fn new(net: &NetArgs, out: &'a Output) -> Result<Logged<'a>, CliError> {
        Ok(Logged {
            inner: ti_idpd::ureq::UreqTransport::new(idp_agent(net)?),
            out,
        })
    }
}

impl ti_idpd::http::Transport for Logged<'_> {
    fn send(
        &self,
        request: &ti_idpd::http::Request,
    ) -> Result<ti_idpd::http::Response, ti_idpd::http::TransportError> {
        let response = self.inner.send(request);
        match &response {
            Ok(r) => {
                self.out.verbose(
                    1,
                    format_args!(
                        "{} {} → {} ({} bytes)",
                        request.method,
                        request.url,
                        r.status,
                        r.body.len()
                    ),
                );
                if !(200..400).contains(&r.status) && !r.body.is_empty() {
                    self.out
                        .verbose(2, String::from_utf8_lossy(&r.body).trim_end());
                }
            }
            Err(e) => self
                .out
                .verbose(1, format_args!("{} {} → {e}", request.method, request.url)),
        }
        response
    }
}

/// `-k`: rustls without a check, for downloads only.
fn insecure_tls() -> TlsConfig {
    TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(RootCerts::new_with_certs(&[]))
        .disable_verification(true)
        .build()
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
pub(crate) fn proxy(net: &NetArgs, scheme: &str) -> Result<Option<ureq::Proxy>, CliError> {
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
    // Without its SOCKS feature, ureq logs such a proxy and connects directly.
    if !matches!(
        parsed.protocol(),
        ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https
    ) {
        return Err(CliError::HttpSetup(format!(
            "proxy {:?}: SOCKS is not supported, use an http:// or https:// proxy",
            redact(&url)
        )));
    }
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
