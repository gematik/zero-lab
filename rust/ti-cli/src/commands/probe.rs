//! `ti probe <ENV>`: whether the TI services of an environment answer, checked in
//! parallel with the protocol each speaks: OIDC discovery for the IDP, RFC 9728
//! discovery for ZETA-protected services, the TI platform's service-discovery catalog
//! (whose instances are probed too), plain HTTP otherwise.
//!
//! Like the Go `ti probe`, TLS is not verified: the question is reachability, and many
//! TI services present certificates of TI-internal CAs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use ti_pki::Env;
use ureq::Agent;
use ureq::tls::{TlsConfig, TlsProvider};

use super::connector::emit;
use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::output::live::Live;
use crate::output::{Line, Output, Tone, style};

/// Every request is given up after this.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The endpoints of each environment; `TI_PROBE_ENDPOINTS_PATH` replaces them.
const ENDPOINTS: &str = include_str!("../probe/endpoints.json");

/// The ePA `x-useragent`, `ClientId/Version`; the aggregators reject other shapes.
const EPA_USER_AGENT: &str = concat!("ti-cli/", env!("CARGO_PKG_VERSION"));

/// A well-formed insurant ID (a letter and nine digits) that belongs to nobody: the
/// Information Service answers `noHealthRecord` for it.
const EPA_INSURANT: &str = "X000000000";

/// Largest body read; discovery documents and catalogs are a few KiB.
const MAX_BODY: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct Endpoint {
    name: String,
    kind: Kind,
    url: String,
}

/// How an endpoint is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    /// OIDC discovery (`/.well-known/openid-configuration`).
    Oidc,
    /// RFC 9728 protected-resource discovery of a ZETA-protected service.
    Zeta,
    /// The TI platform's service-discovery catalog.
    Catalog,
    /// The E-Rezept Fachdienst's VAU certificate (`/VAUCertificate`). Its gateway answers
    /// 200 for any path, so only a certificate proves the Fachdienst.
    Erp,
    /// The ePA Information Service (`/information/api/v1/ehr`): asked without an insurant,
    /// it answers with its JSON error, which a front page or gateway does not.
    Epa,
    /// Any HTTP answer.
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    /// The expected answer.
    Ok,
    /// An answer, but not the expected one.
    Warn,
    /// No answer.
    Fail,
}

/// The outcome of one probe.
struct Outcome {
    status: Status,
    detail: String,
    http_status: Option<u16>,
    duration: Duration,
    /// Endpoints a catalog lists.
    discovered: Vec<Endpoint>,
}

/// One row: an endpoint and, once probed, its outcome.
struct Row {
    endpoint: Endpoint,
    source: &'static str,
    outcome: Option<Outcome>,
}

#[derive(Serialize)]
struct Report {
    environment: &'static str,
    duration_ms: u64,
    counts: Counts,
    probes: Vec<ProbeInfo>,
}

#[derive(Serialize)]
struct Counts {
    ok: usize,
    warn: usize,
    fail: usize,
}

#[derive(Serialize)]
struct ProbeInfo {
    name: String,
    kind: Kind,
    url: String,
    host: String,
    /// `builtin`, or `catalog` for an instance the catalog lists.
    source: &'static str,
    status: Status,
    detail: String,
    http_status: Option<u16>,
    duration_ms: u64,
}

/// Runs `ti probe`.
pub fn run(env: Env, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let endpoints = endpoints(env)?;
    let agent = agent(global)?;
    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    let mut rows: Vec<Row> = Vec::new();
    for endpoint in endpoints {
        spawn(&agent, env, &tx, rows.len(), &endpoint);
        rows.push(Row {
            endpoint,
            source: "builtin",
            outcome: None,
        });
    }
    let text = !out.is_json() && !out.is_markdown();
    let mut live = Live::new();
    let live_view = text && live.enabled();
    let mut tick = 0usize;
    while rows.iter().any(|r| r.outcome.is_none()) {
        if let Ok((index, outcome)) = rx.recv_timeout(Duration::from_millis(100)) {
            for endpoint in &outcome.discovered {
                let known = rows
                    .iter()
                    .any(|r| same_url(&r.endpoint.url, &endpoint.url));
                if !known {
                    spawn(&agent, env, &tx, rows.len(), endpoint);
                    rows.push(Row {
                        endpoint: endpoint.clone(),
                        source: "catalog",
                        outcome: None,
                    });
                }
            }
            let row: &mut Row = &mut rows[index];
            row.outcome = Some(outcome);
            if text && !live_view {
                // Not a terminal: each line once it is final.
                let widths = widths(&rows);
                print_line(&line(&rows[index], &widths, 0));
            }
        }
        tick += 1;
        if live_view {
            live.draw(&lines(&rows, tick));
        }
    }
    let elapsed = start.elapsed();
    let report = report(env, &rows, elapsed);
    let exit = if report.counts.fail > 0 {
        Exit::Invalid
    } else {
        Exit::Ok
    };
    if text {
        if live_view {
            live.finish(&lines(&rows, tick));
        }
        print_line(&summary(&report.counts, elapsed));
        return Ok(exit);
    }
    emit(out, exit, &report, |doc| {
        let rows = report.probes.iter().map(|p| {
            vec![
                Line::strong(&p.name),
                mark(p.status),
                Line::code(&p.host),
                Line::dim(format!("{} ms", p.duration_ms)),
                Line::text(&p.detail),
            ]
        });
        doc.table(&["SERVICE", "", "HOST", "TIME", "DETAIL"], rows.collect());
        doc.paragraph(Line::dim(summary_plain(&report.counts, elapsed)));
    })
}

/// The endpoints of `env`, from `TI_PROBE_ENDPOINTS_PATH` or the embedded list.
fn endpoints(env: Env) -> Result<Vec<Endpoint>, CliError> {
    let text = match std::env::var_os("TI_PROBE_ENDPOINTS_PATH") {
        Some(path) => std::fs::read_to_string(&path).map_err(|e| CliError::Read {
            source_name: path.to_string_lossy().into_owned(),
            source: e,
        })?,
        None => ENDPOINTS.to_owned(),
    };
    let mut all: HashMap<String, Vec<Endpoint>> = serde_json::from_str(&text)
        .map_err(|e| CliError::ConnectorConfig(format!("probe endpoints: {e}")))?;
    Ok(all.remove(env.as_str()).unwrap_or_default())
}

/// ureq without certificate verification, 3 s per request, the proxy and user agent of
/// the HTTP options.
fn agent(global: &GlobalArgs) -> Result<Agent, CliError> {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .disable_verification(true)
        .build();
    Ok(Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .timeout_connect(Some(TIMEOUT))
        .user_agent(global.net.user_agent())
        .tls_config(tls)
        .proxy(crate::http::proxy(&global.net, "https")?)
        .build()
        .new_agent())
}

fn spawn(
    agent: &Agent,
    env: Env,
    tx: &mpsc::Sender<(usize, Outcome)>,
    index: usize,
    endpoint: &Endpoint,
) {
    let (agent, tx, endpoint) = (agent.clone(), tx.clone(), endpoint.clone());
    std::thread::spawn(move || {
        // The receiver outlives every worker; a send cannot fail while it runs.
        let _ = tx.send((index, probe(&agent, env, &endpoint)));
    });
}

/// A styled line on stdout, through the stream that strips styles where colors are off.
fn print_line(line: &str) {
    use std::io::Write as _;
    // A closed stdout (`| head`) ends the output, not the probes' outcome.
    let _ = writeln!(crate::output::stdout(), "{line}");
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Probes `endpoint` the way its kind asks for.
fn probe(agent: &Agent, env: Env, endpoint: &Endpoint) -> Outcome {
    let base = endpoint.url.trim_end_matches('/');
    let url = match endpoint.kind {
        Kind::Oidc => format!("{base}/.well-known/openid-configuration"),
        Kind::Zeta => format!("{base}/.well-known/oauth-protected-resource"),
        Kind::Erp => format!("{base}/VAUCertificate"),
        Kind::Epa => format!("{base}/information/api/v1/ehr"),
        Kind::Catalog | Kind::Http => endpoint.url.clone(),
    };
    let start = Instant::now();
    let mut request = agent.get(&url);
    if endpoint.kind == Kind::Epa {
        request = request
            .header("x-useragent", EPA_USER_AGENT)
            .header("x-insurantid", EPA_INSURANT);
    }
    let answer = request.call().and_then(|mut response| {
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()?;
        Ok((status, body))
    });
    let duration = start.elapsed();
    let (status, body) = match answer {
        Ok(answer) => answer,
        Err(error) => {
            return Outcome {
                status: Status::Fail,
                detail: failure(&error),
                http_status: None,
                duration,
                discovered: Vec::new(),
            };
        }
    };
    let (verdict, detail, discovered) = judge(endpoint.kind, env, base, status, &body);
    Outcome {
        status: verdict,
        detail,
        http_status: Some(status),
        duration,
        discovered,
    }
}

/// What an answer means for an endpoint of `kind`.
fn judge(
    kind: Kind,
    env: Env,
    base: &str,
    status: u16,
    body: &[u8],
) -> (Status, String, Vec<Endpoint>) {
    let warn = |detail: String| (Status::Warn, detail, Vec::new());
    if kind == Kind::Http {
        return (Status::Ok, format!("http {status}"), Vec::new());
    }
    if kind == Kind::Epa {
        let code = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|d| d.get("errorCode")?.as_str().map(str::to_owned));
        return match (status, code.as_deref()) {
            (204, _) | (404, Some("noHealthRecord")) => {
                (Status::Ok, "epa information service".into(), Vec::new())
            }
            (_, Some(code)) => warn(format!("HTTP {status}, {code}")),
            (_, None) => warn(format!("HTTP {status}, no ePA information service")),
        };
    }
    if status != 200 {
        return warn(format!("HTTP {status}"));
    }
    match kind {
        Kind::Oidc => {
            match discovery(body).and_then(|d| d.get("issuer")?.as_str().map(str::to_owned)) {
                Some(issuer) if issuer.trim_end_matches('/').eq_ignore_ascii_case(base) => {
                    (Status::Ok, "oidc discovery".into(), Vec::new())
                }
                Some(issuer) => warn(format!("issuer {issuer} differs")),
                None => warn("no OIDC discovery document".into()),
            }
        }
        Kind::Zeta => {
            let servers = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|d| d.get("authorization_servers")?.as_array().cloned());
            match servers.as_deref() {
                Some([_, ..]) => (Status::Ok, "zeta resource metadata".into(), Vec::new()),
                _ => warn("no RFC 9728 protected-resource metadata".into()),
            }
        }
        Kind::Catalog => catalog(env, body),
        Kind::Erp => match ti_pki::Certificate::from_der(body) {
            Ok(_) => (Status::Ok, "erp VAU certificate".into(), Vec::new()),
            Err(_) => warn("no VAU certificate".into()),
        },
        Kind::Epa | Kind::Http => unreachable!("answered above"),
    }
}

/// An OIDC discovery document: JSON, or the gematik IDP's signed document (a compact
/// JWS whose payload is the JSON).
fn discovery(body: &[u8]) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_slice(body) {
        return Some(value);
    }
    let text = std::str::from_utf8(body).ok()?.trim();
    let payload = text.split('.').nth(1)?;
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload).ok()?).ok()
}

/// The service-discovery catalog: its format, its environment, and the instances it
/// lists, which become further probes.
fn catalog(env: Env, body: &[u8]) -> (Status, String, Vec<Endpoint>) {
    #[derive(Deserialize)]
    struct Catalog {
        format_version: String,
        env: String,
        #[serde(default)]
        service_instances: HashMap<String, Instance>,
    }
    #[derive(Deserialize)]
    struct Instance {
        #[serde(rename = "type")]
        kind: String,
        url: String,
    }
    let Ok(catalog) = serde_json::from_slice::<Catalog>(body) else {
        return (
            Status::Warn,
            "not a service-discovery catalog".into(),
            Vec::new(),
        );
    };
    let mut instances: Vec<(String, Instance)> = catalog.service_instances.into_iter().collect();
    instances.sort_by(|a, b| a.0.cmp(&b.0));
    let discovered = instances
        .into_iter()
        .map(|(id, instance)| Endpoint {
            name: id,
            // PoPP and VSDM are ZETA-protected; the rest is checked for any answer.
            kind: match instance.kind.as_str() {
                "popp" | "vsdm" | "dipag" => Kind::Zeta,
                _ => Kind::Http,
            },
            url: instance.url,
        })
        .collect::<Vec<_>>();
    if catalog.env == env.as_str() {
        let detail = format!("catalog, {} instances", discovered.len());
        (Status::Ok, detail, discovered)
    } else {
        let detail = format!(
            "format {}, env {} instead of {}",
            catalog.format_version,
            catalog.env,
            env.as_str()
        );
        (Status::Warn, detail, discovered)
    }
}

/// A transport failure in a few words, as the Go probe reports it.
fn failure(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timeout".into(),
        ureq::Error::HostNotFound => "DNS lookup failed".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::Io(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            "connection refused".into()
        }
        ureq::Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => "timeout".into(),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS error".into(),
        other => {
            let text = other.to_string();
            // The system resolver's failures come as plain I/O errors.
            let dns = [
                "nodename nor servname",
                "Name or service not known",
                "failed to lookup address",
                "No such host",
                "Temporary failure in name resolution",
            ];
            if dns.iter().any(|d| text.contains(d)) {
                return "DNS lookup failed".into();
            }
            match text.rsplit_once(": ") {
                Some((_, last)) => last.to_owned(),
                None => text,
            }
        }
    }
}

fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_owned()
}

fn mark(status: Status) -> Line {
    match status {
        Status::Ok => Line::status(Tone::Good, "✓"),
        Status::Warn => Line::status(Tone::Warn, "!"),
        Status::Fail => Line::status(Tone::Bad, "✗"),
    }
}

/// Column widths of name and host over all rows, so lines align.
fn widths(rows: &[Row]) -> (usize, usize) {
    rows.iter().fold((7, 4), |(n, h), r| {
        (
            n.max(r.endpoint.name.chars().count()),
            h.max(host(&r.endpoint.url).chars().count()),
        )
    })
}

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// One row as a styled terminal line: `SERVICE  ✓  HOST  DETAIL  TIME`.
fn line(row: &Row, (name_width, host_width): &(usize, usize), tick: usize) -> String {
    let (strong, dim) = (style::EMPHASIS, style::DIM);
    let name = |tone: anstyle::Style| format!("{tone}{:name_width$}{tone:#}", row.endpoint.name);
    let host = format!("{:host_width$}", host(&row.endpoint.url));
    match &row.outcome {
        None => {
            let frame = SPINNER[tick % SPINNER.len()];
            format!("{}  {dim}{frame}{dim:#}  {host}", name(strong))
        }
        Some(o) => {
            let (tone, symbol) = match o.status {
                Status::Ok => (style::GOOD, "✓"),
                Status::Warn => (style::WARN, "!"),
                Status::Fail => (style::BAD, "✗"),
            };
            let ms = o.duration.as_millis();
            let plain = anstyle::Style::new().fg_color(tone.get_fg_color());
            format!(
                "{}  {tone}{symbol}{tone:#}  {host}  {dim}{ms:>4} ms{dim:#}  {plain}{}{plain:#}",
                name(tone),
                o.detail
            )
        }
    }
}

fn lines(rows: &[Row], tick: usize) -> Vec<String> {
    let widths = widths(rows);
    let label = style::LABEL;
    let mut lines = vec![format!(
        "{label}{:w0$}     {:w1$}     TIME  DETAIL{label:#}",
        "SERVICE",
        "HOST",
        w0 = widths.0,
        w1 = widths.1
    )];
    lines.extend(rows.iter().map(|r| line(r, &widths, tick)));
    lines
}

fn report(env: Env, rows: &[Row], elapsed: Duration) -> Report {
    let probes: Vec<ProbeInfo> = rows
        .iter()
        .filter_map(|r| {
            let o = r.outcome.as_ref()?;
            Some(ProbeInfo {
                name: r.endpoint.name.clone(),
                kind: r.endpoint.kind,
                url: r.endpoint.url.clone(),
                host: host(&r.endpoint.url),
                source: r.source,
                status: o.status,
                detail: o.detail.clone(),
                http_status: o.http_status,
                duration_ms: u64::try_from(o.duration.as_millis()).unwrap_or(u64::MAX),
            })
        })
        .collect();
    let count = |s: Status| probes.iter().filter(|p| p.status == s).count();
    Report {
        environment: env.as_str(),
        duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        counts: Counts {
            ok: count(Status::Ok),
            warn: count(Status::Warn),
            fail: count(Status::Fail),
        },
        probes,
    }
}

fn summary_plain(counts: &Counts, elapsed: Duration) -> String {
    format!(
        "{} ok · {} warn · {} failed · {:.1} s",
        counts.ok,
        counts.warn,
        counts.fail,
        elapsed.as_secs_f64()
    )
}

fn summary(counts: &Counts, elapsed: Duration) -> String {
    let (good, warn, bad, dim) = (style::GOOD, style::WARN, style::BAD, style::DIM);
    let failed = if counts.fail > 0 {
        format!("{bad}{} failed{bad:#}", counts.fail)
    } else {
        "0 failed".to_owned()
    };
    let warned = if counts.warn > 0 {
        format!("{warn}{} warn{warn:#}", counts.warn)
    } else {
        "0 warn".to_owned()
    };
    format!(
        "{good}{} ok{good:#} · {warned} · {failed} {dim}· {:.1} s{dim:#}",
        counts.ok,
        elapsed.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_environment_has_valid_endpoints() {
        let all: HashMap<String, Vec<Endpoint>> = serde_json::from_str(ENDPOINTS).unwrap();
        for env in [Env::Prod, Env::Ref, Env::Test, Env::Dev] {
            let list = &all[env.as_str()];
            assert!(list.iter().any(|e| e.kind == Kind::Catalog), "{env:?}");
            assert!(
                list.iter().all(|e| e.url.starts_with("https://")),
                "{env:?}"
            );
        }
    }

    #[test]
    fn oidc_discovery_as_json_or_signed() {
        let json = br#"{"issuer":"https://idp.example"}"#;
        assert_eq!(
            judge(Kind::Oidc, Env::Ref, "https://idp.example", 200, json).0,
            Status::Ok
        );
        let jws = format!(
            "eyJhbGciOiJCUDI1NlIxIn0.{}.c2ln",
            Base64UrlUnpadded::encode_string(json)
        );
        let (status, detail, _) = judge(
            Kind::Oidc,
            Env::Ref,
            "https://idp.example",
            200,
            jws.as_bytes(),
        );
        assert_eq!((status, detail.as_str()), (Status::Ok, "oidc discovery"));
        assert_eq!(
            judge(Kind::Oidc, Env::Ref, "https://other", 200, json).0,
            Status::Warn
        );
        assert_eq!(
            judge(Kind::Oidc, Env::Ref, "https://idp.example", 404, b"").1,
            "HTTP 404"
        );
    }

    #[test]
    fn zeta_protected_resource_metadata() {
        let body = br#"{"resource":"https://popp.dev.poppservice.de","authorization_servers":["https://as.example"]}"#;
        let (status, detail, _) = judge(
            Kind::Zeta,
            Env::Dev,
            "https://popp.dev.poppservice.de",
            200,
            body,
        );
        assert_eq!(
            (status, detail.as_str()),
            (Status::Ok, "zeta resource metadata")
        );
        assert_eq!(judge(Kind::Zeta, Env::Dev, "x", 200, b"{}").0, Status::Warn);
    }

    #[test]
    fn the_catalog_lists_further_probes() {
        let dev = include_bytes!("../../tests/fixtures/catalog-dev.json");
        let (status, detail, found) = judge(Kind::Catalog, Env::Dev, "x", 200, dev);
        assert_eq!(
            (status, detail.as_str()),
            (Status::Ok, "catalog, 6 instances")
        );
        let popp = found.iter().find(|e| e.name == "popp-1").unwrap();
        assert_eq!(
            (popp.kind, popp.url.as_str()),
            (Kind::Zeta, "https://popp.dev.poppservice.de")
        );
        assert_eq!(
            found.iter().find(|e| e.name == "dipag-1").unwrap().kind,
            Kind::Zeta
        );
        let (status, detail, _) = judge(Kind::Catalog, Env::Prod, "x", 200, dev);
        assert_eq!(status, Status::Warn, "{detail}");
    }

    #[test]
    fn epa_information_service_record_status() {
        let none = br#"{"errorCode":"noHealthRecord"}"#;
        let malformed = br#"{"errorCode":"malformedRequest"}"#;
        assert_eq!(judge(Kind::Epa, Env::Dev, "x", 404, none).0, Status::Ok);
        assert_eq!(judge(Kind::Epa, Env::Dev, "x", 204, b"").0, Status::Ok);
        let (status, detail, _) = judge(Kind::Epa, Env::Dev, "x", 400, malformed);
        assert_eq!(status, Status::Warn);
        assert_eq!(detail, "HTTP 400, malformedRequest");
        assert_eq!(judge(Kind::Epa, Env::Dev, "x", 404, b"4o4").0, Status::Warn);
    }

    #[test]
    fn resolver_failures_are_dns_failures() {
        let error = ureq::Error::Io(std::io::Error::other(
            "failed to lookup address information: nodename nor servname provided, or not known",
        ));
        assert_eq!(failure(&error), "DNS lookup failed");
        assert_eq!(failure(&ureq::Error::HostNotFound), "DNS lookup failed");
    }

    #[test]
    fn hosts_and_urls() {
        assert_eq!(
            host("https://epa-as-1.dev.epa4all.de/x?y"),
            "epa-as-1.dev.epa4all.de"
        );
        assert!(same_url("https://a/", "https://a"));
    }
}
