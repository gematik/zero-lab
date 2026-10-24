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

//! `ti probe <ENV>`: whether the TI services of an environment answer, checked in
//! parallel with the protocol each speaks: OIDC discovery for the IDP, RFC 9728
//! discovery for ZETA-protected services, the TI platform's service-discovery catalog
//! (whose instances are probed too), plain HTTP otherwise.
//!
//! Like the Go `ti probe`, TLS is not verified: the question is reachability, and many
//! TI services present certificates of TI-internal CAs.
//!
//! The endpoints are grouped by how they are reached: through the TI VPN of a Konnektor
//! or TI-Gateway, or from the internet. Without the VPN none of the first answers, and
//! the probe says so once for the block.

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

/// Easter egg: `probe def`, a slip for `dev`, answered with a banner before the dev probes: tall
/// letters with spiked ends, filled yellow-orange and edged red.
const DEF: [&str; 8] = [
    "◢◣     ◢◣    ◢◣       ◢◣    ◢◣    ◢◣    ◢◣      ◢◣   ◢◣     ◢◣",
    "███◣   ████◣ ████◣    ██    ████◣ ███◣  ███◣   ◢██◣  ███◣   ███◣",
    "██◥█◣  ██    ██       ██    ██    ██◥█◣ ██◥█◣ ◢█◤◥█◣ ██◥█◣  ██◥█◣",
    "██ ◥█◣ ███◣  ███◣     ██    ███◣  ██◢█◤ ██◢█◤ ██████ ██◢█◤  ██ ◥█◣",
    "██ ◢█◤ ███◤  ███◤     ██    ███◤  ███◤  ███◤  ██  ██ ███◣   ██ ◢█◤",
    "██◢█◤  ██    ██       ██    ██    ██    ██    ██  ██ ██◥█◣  ██◢█◤",
    "███◤   ████◤ ██       ████◣ ████◤ ██    ██    ██  ██ ██ ◥█◣ ███◤",
    "◥◤     ◥◤    ◥◤       ◥◤    ◥◤    ◥◤    ◥◤    ◥◤  ◥◤ ◥◤  ◥◤ ◥◤",
];
const DEF_FILL: anstyle::Style = anstyle::RgbColor(255, 170, 0).on_default().bold();
const DEF_EDGE: anstyle::Style = anstyle::RgbColor(220, 20, 20).on_default().bold();

/// Largest body read; discovery documents and catalogs are a few KiB.
const MAX_BODY: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct Endpoint {
    name: String,
    access: Access,
    kind: Kind,
    url: String,
}

/// How an endpoint is reached; part of the endpoint data, never inferred from its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Access {
    /// Only through a Konnektor's or TI-Gateway's VPN.
    TiVpn,
    /// Directly.
    Internet,
    /// Through the TI VPN into a Bestandsnetz (gematik's Bestandsnetze.xml), which the
    /// Konnektor routes only when the practice has booked it.
    Bestandsnetz,
}

impl Access {
    /// The order the groups are shown in.
    const ALL: [Access; 3] = [Access::TiVpn, Access::Internet, Access::Bestandsnetz];

    fn label(self) -> &'static str {
        match self {
            Access::TiVpn => "TI-VPN",
            Access::Internet => "Internet",
            Access::Bestandsnetz => "Bestandsnetze",
        }
    }

    /// Whether the services of this path are expected to answer. A practice need not
    /// book a Bestandsnetz, so not reaching one is a warning, not a failure.
    fn required(self) -> bool {
        self != Access::Bestandsnetz
    }

    /// Said once for the block when none of its endpoints answered.
    fn unreachable(self) -> &'static str {
        match self {
            Access::TiVpn => "not reachable: no TI VPN?",
            Access::Internet => "not reachable: no internet?",
            Access::Bestandsnetz => "not reachable: not routed by the Konnektor, or no TI VPN?",
        }
    }
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
    /// The FHIR-Directory's owner authentication (`/owner-authenticate`): without a token
    /// it redirects to the IDP-Dienst, which a front page or gateway does not.
    Directory,
    /// Any HTTP answer.
    Http,
    /// A TCP connection to a DNS server (`dns://ADDRESS`, port 53 unless `ADDRESS:PORT`):
    /// proves the route into a Bestandsnetz without a host to ask.
    Dns,
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
    /// The endpoint answered; false for a transport failure, whatever the status.
    answered: bool,
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
    /// Per access path, whether any of its endpoints answered.
    access_paths: Vec<AccessPath>,
    probes: Vec<ProbeInfo>,
}

#[derive(Serialize)]
struct AccessPath {
    access: Access,
    /// False when every endpoint reached this way failed: the path itself is down (for
    /// `ti-vpn`, no TI VPN), not the services.
    available: bool,
    probes: usize,
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
    access: Access,
    kind: Kind,
    url: String,
    host: String,
    /// `builtin`, or `catalog` for an instance the catalog lists.
    source: &'static str,
    status: Status,
    /// The endpoint answered; false for a transport failure.
    answered: bool,
    detail: String,
    http_status: Option<u16>,
    duration_ms: u64,
}

/// Runs `ti probe`.
pub fn run(env: Env, def: bool, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
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
    if def && live_view {
        for line in DEF {
            print_line(&def_line(line));
        }
        let dim = style::DIM;
        print_line(&format!("{dim}pour some sugar on dev{dim:#}\n"));
    }
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
        } else {
            // Not a terminal: the groups once every probe is final.
            for line in lines(&rows, tick) {
                print_line(&line);
            }
        }
        print_line("");
        print_line(&summary(&report, elapsed));
        return Ok(exit);
    }
    emit(out, exit, &report, |doc| {
        for path in &report.access_paths {
            doc.section(path.access.label());
            if !path.available {
                doc.paragraph(Line::dim(path.access.unreachable()));
            }
            let group = || report.probes.iter().filter(|p| p.access == path.access);
            let rows = group()
                .filter(|p| p.access.required() || p.answered)
                .map(|p| {
                    vec![
                        Line::strong(&p.name),
                        mark(p.status),
                        Line::code(&p.host),
                        Line::dim(format!("{} ms", p.duration_ms)),
                        Line::text(&p.detail),
                    ]
                });
            doc.table(&["SERVICE", "", "HOST", "TIME", "DETAIL"], rows.collect());
            if !path.access.required() && group().any(|p| !p.answered) {
                let silent = group().filter(|p| !p.answered).map(|p| p.name.as_str());
                doc.paragraph(Line::text(not_routed(silent)));
            }
        }
        doc.paragraph(Line::dim(summary_plain(&report, elapsed)));
    })
}

/// Whether any endpoint reached by `access` answered: `None` while one is still
/// pending, or when there is none. The answer, not the status, counts: an unreachable
/// Bestandsnetz is a warning, yet the path is down.
fn available(rows: &[Row], access: Access) -> Option<bool> {
    let group: Vec<&Row> = rows
        .iter()
        .filter(|r| r.endpoint.access == access)
        .collect();
    if group.is_empty() {
        return None;
    }
    let mut outcomes = group.iter().map(|r| r.outcome.as_ref());
    if outcomes.clone().any(|o| o.is_none()) {
        return None;
    }
    Some(outcomes.any(|o| o.is_some_and(|o| o.answered)))
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
/// A banner line: blocks in the fill colour, the triangles that edge them in red.
fn def_line(line: &str) -> String {
    line.chars()
        .map(|c| match c {
            '█' => format!("{DEF_FILL}{c}{DEF_FILL:#}"),
            '◢' | '◣' | '◤' | '◥' => format!("{DEF_EDGE}{c}{DEF_EDGE:#}"),
            _ => c.to_string(),
        })
        .collect()
}

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
    if endpoint.kind == Kind::Dns {
        return dns(endpoint);
    }
    let base = endpoint.url.trim_end_matches('/');
    let url = match endpoint.kind {
        Kind::Oidc => format!("{base}/.well-known/openid-configuration"),
        Kind::Zeta => format!("{base}/.well-known/oauth-protected-resource"),
        Kind::Erp => format!("{base}/VAUCertificate"),
        Kind::Epa => format!("{base}/information/api/v1/ehr"),
        Kind::Directory => format!("{base}/owner-authenticate"),
        Kind::Catalog | Kind::Http | Kind::Dns => endpoint.url.clone(),
    };
    let start = Instant::now();
    let mut request = agent.get(&url);
    if endpoint.kind == Kind::Epa {
        request = request
            .header("x-useragent", EPA_USER_AGENT)
            .header("x-insurantid", EPA_INSURANT);
    }
    // The redirect is the answer; following it would probe the IDP instead.
    if endpoint.kind == Kind::Directory {
        request = request.config().max_redirects(0).build();
    }
    let answer = request.call().and_then(|mut response| {
        let status = response.status().as_u16();
        if endpoint.kind == Kind::Directory {
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            return Ok((status, location.as_bytes().to_vec()));
        }
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
                status: unanswered(endpoint.access),
                answered: false,
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
        answered: true,
        detail,
        http_status: Some(status),
        duration,
        discovered,
    }
}

/// The status of an endpoint that did not answer: a failure, except on a path whose
/// services need not be reachable.
fn unanswered(access: Access) -> Status {
    if access.required() {
        Status::Fail
    } else {
        Status::Warn
    }
}

/// Connects to the DNS server in `endpoint`'s `dns://ADDRESS`. Direct, not through the
/// HTTP proxy: the route itself is what is probed.
fn dns(endpoint: &Endpoint) -> Outcome {
    let start = Instant::now();
    let connected = dns_server(&host(&endpoint.url)).and_then(|server| {
        std::net::TcpStream::connect_timeout(&server, TIMEOUT)
            .map(|_| server.port())
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut => "timeout".to_owned(),
                std::io::ErrorKind::ConnectionRefused => "connection refused".to_owned(),
                _ => e.to_string(),
            })
    });
    let duration = start.elapsed();
    let (status, answered, detail) = match connected {
        Ok(port) => (Status::Ok, true, format!("dns, port {port} open")),
        Err(detail) => (unanswered(endpoint.access), false, detail),
    };
    Outcome {
        status,
        answered,
        detail,
        http_status: None,
        duration,
        discovered: Vec::new(),
    }
}

/// `IP` (port 53) or `IP:PORT`; names are refused, since resolving one would ask the
/// DNS the probe is meant to check the route to.
fn dns_server(address: &str) -> Result<std::net::SocketAddr, String> {
    address
        .parse::<std::net::SocketAddr>()
        .or_else(|_| {
            address
                .parse::<std::net::IpAddr>()
                .map(|ip| (ip, 53).into())
        })
        .map_err(|_| format!("{address} is not an IP address"))
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
    if kind == Kind::Directory {
        return directory(status, body);
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
        Kind::Epa | Kind::Directory | Kind::Http | Kind::Dns => unreachable!("answered above"),
    }
}

/// The FHIR-Directory's answer to `/owner-authenticate`; `location` is the redirect's
/// `Location` (the body is not read).
fn directory(status: u16, location: &[u8]) -> (Status, String, Vec<Endpoint>) {
    let location = String::from_utf8_lossy(location);
    let authorization = location.starts_with("https://") && location.contains("client_id=");
    match status {
        300..=399 if authorization => (Status::Ok, "directory owner auth".into(), Vec::new()),
        300..=399 => (
            Status::Warn,
            format!("HTTP {status}, no IDP authorization URL"),
            Vec::new(),
        ),
        _ => (
            Status::Warn,
            format!("HTTP {status}, no owner-authenticate redirect"),
            Vec::new(),
        ),
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
            // The catalog is the internet platform's; its instances are reached the same way.
            access: Access::Internet,
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

/// One row as a styled terminal line: `SERVICE  ✓  HOST  DETAIL  TIME`; all of it gray
/// in a block whose access path is down.
fn line(row: &Row, (name_width, host_width): &(usize, usize), tick: usize, gray: bool) -> String {
    let (strong, dim) = (style::EMPHASIS, style::DIM);
    let name = |tone: anstyle::Style| format!("{tone}{:name_width$}{tone:#}", row.endpoint.name);
    let host = format!("{:host_width$}", host(&row.endpoint.url));
    if gray && let Some(o) = &row.outcome {
        let ms = o.duration.as_millis();
        return format!(
            "{dim}{:name_width$}  ✗  {host}  {ms:>4} ms  {}{dim:#}",
            row.endpoint.name, o.detail
        );
    }
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

/// Rows sit this far in under their access path's heading.
const INDENT: &str = "  ";

/// The table: the column headings, then a block per access path, its heading flush left
/// and its rows indented below; a block whose path is down says so on its heading, and
/// its rows are gray.
fn lines(rows: &[Row], tick: usize) -> Vec<String> {
    let widths = widths(rows);
    let label = style::LABEL;
    let mut lines = vec![format!(
        "{INDENT}{label}{:w0$}     {:w1$}     TIME  DETAIL{label:#}",
        "SERVICE",
        "HOST",
        w0 = widths.0,
        w1 = widths.1
    )];
    for access in Access::ALL {
        let group: Vec<&Row> = rows
            .iter()
            .filter(|r| r.endpoint.access == access)
            .collect();
        if group.is_empty() {
            continue;
        }
        let down = available(rows, access) == Some(false);
        lines.push(String::new());
        // The heading stays prominent either way; a path that is down says so after it.
        let strong = style::EMPHASIS;
        lines.push(if down {
            let warn = style::WARN;
            format!(
                "{strong}{}{strong:#} {warn}· {}{warn:#}",
                access.label(),
                access.unreachable()
            )
        } else {
            format!("{strong}{}{strong:#}", access.label())
        });
        if access.required() {
            lines.extend(
                group
                    .iter()
                    .map(|r| format!("{INDENT}{}", line(r, &widths, tick, down))),
            );
            continue;
        }
        // Most practices book few Bestandsnetze: the ones not routed share one line.
        let (silent, shown): (Vec<&Row>, Vec<&Row>) = group
            .iter()
            .partition(|r| r.outcome.as_ref().is_some_and(|o| !o.answered));
        lines.extend(
            shown
                .iter()
                .map(|r| format!("{INDENT}{}", line(r, &widths, tick, false))),
        );
        if !silent.is_empty() {
            let warn = style::WARN;
            lines.push(format!(
                "{INDENT}{warn}! {}{warn:#}",
                not_routed(silent.iter().map(|r| r.endpoint.name.as_str()))
            ));
        }
    }
    lines
}

/// The one line for the Bestandsnetze that did not answer.
fn not_routed<'a>(names: impl Iterator<Item = &'a str>) -> String {
    format!("not routed: {}", names.collect::<Vec<_>>().join(", "))
}

fn report(env: Env, rows: &[Row], elapsed: Duration) -> Report {
    let probes: Vec<ProbeInfo> = rows
        .iter()
        .filter_map(|r| {
            let o = r.outcome.as_ref()?;
            Some(ProbeInfo {
                name: r.endpoint.name.clone(),
                access: r.endpoint.access,
                kind: r.endpoint.kind,
                url: r.endpoint.url.clone(),
                host: host(&r.endpoint.url),
                source: r.source,
                status: o.status,
                answered: o.answered,
                detail: o.detail.clone(),
                http_status: o.http_status,
                duration_ms: u64::try_from(o.duration.as_millis()).unwrap_or(u64::MAX),
            })
        })
        .collect();
    let count = |s: Status| probes.iter().filter(|p| p.status == s).count();
    let access_paths = Access::ALL
        .into_iter()
        .filter_map(|access| {
            Some(AccessPath {
                access,
                available: available(rows, access)?,
                probes: probes.iter().filter(|p| p.access == access).count(),
            })
        })
        .collect();
    Report {
        environment: env.as_str(),
        duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        counts: Counts {
            ok: count(Status::Ok),
            warn: count(Status::Warn),
            fail: count(Status::Fail),
        },
        access_paths,
        probes,
    }
}

/// ` · TI-VPN not reachable` for each access path that is down.
fn paths_down(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut down = String::new();
    for path in report.access_paths.iter().filter(|p| !p.available) {
        let _ = write!(down, " · {} not reachable", path.access.label());
    }
    down
}

fn summary_plain(report: &Report, elapsed: Duration) -> String {
    let counts = &report.counts;
    format!(
        "{} ok · {} warn · {} failed{} · {:.1} s",
        counts.ok,
        counts.warn,
        counts.fail,
        paths_down(report),
        elapsed.as_secs_f64()
    )
}

fn summary(report: &Report, elapsed: Duration) -> String {
    let counts = &report.counts;
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
        "{good}{} ok{good:#} · {warned} · {failed}{} {dim}· {:.1} s{dim:#}",
        counts.ok,
        paths_down(report),
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
            for e in list {
                let valid = match e.kind {
                    Kind::Dns => dns_server(&host(&e.url)).is_ok(),
                    _ => e.url.starts_with("https://"),
                };
                assert!(valid, "{env:?}: {}", e.url);
            }
        }
    }

    /// Lowercase kebab-case names, `<service>-<n>` for numbered instances, the IDP named
    /// after the network it serves; and each IDP in its own block.
    #[test]
    fn endpoint_names_follow_the_convention() {
        let all: HashMap<String, Vec<Endpoint>> = serde_json::from_str(ENDPOINTS).unwrap();
        let kebab = |name: &str| {
            !name.is_empty()
                && name.split('-').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
        };
        for (env, list) in &all {
            for e in list {
                assert!(kebab(&e.name), "{env}: {}", e.name);
            }
            let access = |name: &str| list.iter().find(|e| e.name == name).map(|e| e.access);
            assert_eq!(access("idpd-ti"), Some(Access::TiVpn), "{env}");
            assert_eq!(access("idpd-internet"), Some(Access::Internet), "{env}");
            assert_eq!(access("catalog"), Some(Access::Internet), "{env}");
        }
    }

    /// gematik's Bestandsnetze.xml lists 17 networks; each is probed in prod, on its own
    /// path, through a known HTTPS host or its first DNS server.
    #[test]
    fn prod_probes_every_bestandsnetz() {
        let all: HashMap<String, Vec<Endpoint>> = serde_json::from_str(ENDPOINTS).unwrap();
        let networks: Vec<&Endpoint> = all["prod"]
            .iter()
            .filter(|e| e.access == Access::Bestandsnetz)
            .collect();
        assert_eq!(networks.len(), 17);
        let snk = networks.iter().find(|e| e.name == "snk").unwrap();
        assert_eq!(
            (snk.kind, snk.url.as_str()),
            (Kind::Http, "https://portal.kv-safenet.de")
        );
        assert!(
            networks
                .iter()
                .all(|e| matches!(e.kind, Kind::Http | Kind::Dns))
        );
    }

    #[test]
    fn an_unreachable_bestandsnetz_is_a_warning_elsewhere_a_failure() {
        assert_eq!(unanswered(Access::Bestandsnetz), Status::Warn);
        assert_eq!(unanswered(Access::TiVpn), Status::Fail);
        assert_eq!(unanswered(Access::Internet), Status::Fail);
    }

    #[test]
    fn dns_servers_are_addresses_with_port_53_by_default() {
        assert_eq!(
            dns_server("188.144.7.140"),
            Ok("188.144.7.140:53".parse().unwrap())
        );
        assert_eq!(
            dns_server("127.0.0.1:5353"),
            Ok("127.0.0.1:5353".parse().unwrap())
        );
        assert!(dns_server("dns.kv-safenet.de").is_err());
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
    fn directory_owner_authenticate_redirects_to_the_idp() {
        let idp = b"https://idp-ref.app.ti-dienste.de/auth?response_type=code&client_id=GEMx";
        let (status, detail, _) = judge(Kind::Directory, Env::Ref, "x", 302, idp);
        assert_eq!(status, Status::Ok);
        assert_eq!(detail, "directory owner auth");
        let (status, detail, _) = judge(Kind::Directory, Env::Ref, "x", 302, b"/login");
        assert_eq!(
            (status, detail.as_str()),
            (Status::Warn, "HTTP 302, no IDP authorization URL")
        );
        let (status, detail, _) = judge(Kind::Directory, Env::Ref, "x", 200, b"");
        assert_eq!(
            (status, detail.as_str()),
            (Status::Warn, "HTTP 200, no owner-authenticate redirect")
        );
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
