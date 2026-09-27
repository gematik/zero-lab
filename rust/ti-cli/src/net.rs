//! HTTP options shared by every command that downloads or queries OCSP, modelled on
//! curl's flags so they read the same.

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;

/// curl-like HTTP options.
#[derive(Clone, Debug, Args)]
#[command(next_help_heading = "HTTP options")]
pub struct NetArgs {
    /// Skip TLS certificate checks for downloads (like curl -k); validation results are
    /// unaffected, as trust material is verified cryptographically
    #[arg(short = 'k', long, global = true)]
    pub insecure: bool,
    /// PEM file of CA certificates trusted instead of the OS store (like curl --cacert);
    /// repeatable [env: CURL_CA_BUNDLE, SSL_CERT_FILE]
    #[arg(long, value_name = "FILE", global = true)]
    pub cacert: Vec<PathBuf>,
    /// Directory of PEM CA certificates trusted instead of the OS store [env: SSL_CERT_DIR]
    #[arg(long, value_name = "DIR", global = true)]
    pub capath: Option<PathBuf>,
    /// Proxy URL (http://, https://, socks5://); "" disables proxies
    /// [env: HTTPS_PROXY, HTTP_PROXY, ALL_PROXY]
    #[arg(short = 'x', long, value_name = "URL", value_parser = proxy_url, global = true)]
    pub proxy: Option<String>,
    /// Comma-separated hosts reached without proxy; "*" for all [env: NO_PROXY]
    #[arg(long, value_name = "LIST", global = true)]
    pub noproxy: Option<String>,
    /// Seconds to wait for a connection
    #[arg(long, value_name = "SECS", default_value = "10", value_parser = seconds, global = true)]
    pub connect_timeout: Duration,
    /// Maximum seconds per request
    #[arg(short = 'm', long, value_name = "SECS", default_value = "60", value_parser = seconds, global = true)]
    pub max_time: Duration,
    /// Retries on transient failures (connection errors, HTTP 5xx and 429)
    #[arg(long, value_name = "N", default_value_t = 0, global = true)]
    pub retry: u32,
    /// User-Agent header [default: tir/VERSION]
    #[arg(short = 'A', long, value_name = "STRING", global = true)]
    pub user_agent: Option<String>,
}

/// Seconds as curl takes them: a positive number, fractions allowed.
fn seconds(value: &str) -> Result<Duration, String> {
    let secs: f64 = value
        .parse()
        .map_err(|_| format!("{value:?} is not a number of seconds"))?;
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("{value:?} must be a positive number of seconds"));
    }
    Duration::try_from_secs_f64(secs).map_err(|e| e.to_string())
}

fn proxy_url(value: &str) -> Result<String, String> {
    const SCHEMES: [&str; 4] = ["http://", "https://", "socks5://", "socks5h://"];
    if value.is_empty() || SCHEMES.iter().any(|s| value.starts_with(s)) {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "{value:?} must start with one of {}",
            SCHEMES.join(", ")
        ))
    }
}

impl NetArgs {
    /// The CA files and directory that replace the OS store: the options, else curl's
    /// environment variables (`CURL_CA_BUNDLE`, then `SSL_CERT_FILE`; `SSL_CERT_DIR`).
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

    /// The effective user agent.
    pub fn user_agent(&self) -> String {
        self.user_agent
            .clone()
            .unwrap_or_else(|| concat!("tir/", env!("CARGO_PKG_VERSION")).to_owned())
    }
}

/// One line for `-v`, without proxy credentials.
impl fmt::Display for NetArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trust = if self.insecure {
            "NOT VERIFIED (-k)".to_owned()
        } else {
            let (files, dir) = self.ca_sources();
            if files.is_empty() && dir.is_none() {
                "OS trust store".to_owned()
            } else {
                files
                    .iter()
                    .chain(dir.iter())
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        let proxy = match self.proxy.as_deref() {
            None => "from environment".to_owned(),
            Some("") => "none".to_owned(),
            Some(url) => redact(url),
        };
        write!(
            f,
            "tls {trust}; proxy {proxy}{}; connect {:?}, max {:?}, retry {}; agent {}",
            self.noproxy
                .as_deref()
                .map_or_else(String::new, |list| format!(" (except {list})")),
            self.connect_timeout,
            self.max_time,
            self.retry,
            self.user_agent()
        )
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_like_curl() {
        assert_eq!(seconds("10"), Ok(Duration::from_secs(10)));
        assert_eq!(seconds("2.5"), Ok(Duration::from_millis(2500)));
        for bad in ["0", "-1", "abc", "inf", "NaN"] {
            assert!(seconds(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_schemes_and_redaction() {
        assert!(proxy_url("http://proxy:3128").is_ok());
        assert!(proxy_url("").is_ok());
        assert!(proxy_url("proxy:3128").is_err());
        assert_eq!(
            redact("http://user:secret@proxy:3128"),
            "http://***@proxy:3128"
        );
        assert_eq!(redact("http://proxy:3128"), "http://proxy:3128");
    }
}
