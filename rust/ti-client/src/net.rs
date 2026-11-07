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

//! The HTTP settings of a host, modelled on curl's options so a command-line front end can
//! take them as curl's flags, and the proxy as curl picks it.

use std::path::PathBuf;
use std::time::Duration;

use ureq::Agent;
use ureq::config::ConfigBuilder;
use ureq::typestate::AgentScope;

pub use crate::error::Error;

/// curl-like HTTP settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    /// Skip TLS certificate checks for downloads (curl's `-k`); trust material is verified by
    /// its content regardless.
    pub insecure: bool,
    /// PEM files of CA certificates trusted instead of the operating system's (`--cacert`).
    pub cacert: Vec<PathBuf>,
    /// A directory of PEM CA certificates trusted instead of the operating system's
    /// (`--capath`).
    pub capath: Option<PathBuf>,
    /// The proxy URL (`-x`); `Some("")` disables proxies, `None` takes them from the
    /// environment.
    pub proxy: Option<String>,
    /// Comma-separated hosts reached without proxy, `*` for all (`--noproxy`); `None` takes
    /// them from the environment.
    pub noproxy: Option<String>,
    /// How long to wait for a connection.
    pub connect_timeout: Duration,
    /// How long a request may take.
    pub max_time: Duration,
    /// Retries on transient failures: connection errors, HTTP 5xx and 429.
    pub retry: u32,
    /// The `User-Agent` header.
    pub user_agent: String,
}

impl Net {
    /// The CA files and directory that replace the operating system's store: the settings,
    /// else curl's environment variables (`CURL_CA_BUNDLE`, then `SSL_CERT_FILE`;
    /// `SSL_CERT_DIR`).
    pub fn ca_sources(&self) -> (Vec<PathBuf>, Option<PathBuf>) {
        if !self.cacert.is_empty() || self.capath.is_some() {
            return (self.cacert.clone(), self.capath.clone());
        }
        let var = |name| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let file = var("CURL_CA_BUNDLE").or_else(|| var("SSL_CERT_FILE"));
        (file.into_iter().collect(), var("SSL_CERT_DIR"))
    }

    /// The proxy given explicitly (`-x`), if any; the environment's does not count.
    pub fn explicit_proxy(&self) -> Option<&str> {
        self.proxy.as_deref().filter(|p| !p.is_empty())
    }
}

/// curl's settings for requests to `scheme` URLs: proxy, timeouts, user agent; statuses
/// are never errors.
///
/// # Errors
///
/// [`Error::Setup`] for an unusable proxy.
pub fn builder(net: &Net, scheme: &str) -> Result<ConfigBuilder<AgentScope>, Error> {
    Ok(Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(net.connect_timeout))
        .timeout_global(Some(net.max_time))
        .user_agent(&net.user_agent)
        .proxy(proxy(net, scheme)?))
}

/// The proxy for URLs of `scheme`, as curl picks it: `-x`, else `<scheme>_proxy`, else
/// `ALL_PROXY`, each variable lower case first; `--noproxy`, else `NO_PROXY`, exempts
/// hosts. `-x ""` or a no-proxy list of `*` turns proxies off.
///
/// # Errors
///
/// [`Error::Setup`] for a proxy that is no URL or a SOCKS proxy.
pub fn proxy(net: &Net, scheme: &str) -> Result<Option<ureq::Proxy>, Error> {
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
    let invalid = |_| Error::Setup(format!("proxy {:?} is not a valid URL", redact(&url)));
    let parsed = ureq::Proxy::new(&url).map_err(invalid)?;
    // Without its SOCKS feature, ureq logs such a proxy and connects directly.
    if !matches!(
        parsed.protocol(),
        ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https
    ) {
        return Err(Error::Setup(format!(
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

/// `scheme://user:secret@host` → `scheme://***@host`.
pub fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    match rest.split_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}"),
        None => url.to_owned(),
    }
}
