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

//! Whether the TI services of an environment answer from this host, checked in parallel
//! with the protocol each speaks: OIDC discovery for the IDP, RFC 9728 discovery for
//! ZETA-protected services, the TI platform's service-discovery catalog (whose instances
//! are probed too), plain HTTP otherwise.
//!
//! Every https endpoint is verified under the profile of `spec/pki-validation` its data
//! names: `ti` (the environment's TSL and roots, OCSP) for the services that present TI
//! certificates, such as ePA, and `web` (the operating system's roots) for the rest, the
//! IDP-Dienst and the E-Rezept Fachdienst included. A refused certificate is an answer
//! and a failure: reachable is not trustworthy.
//!
//! The endpoints are grouped by how they are reached: through the TI VPN of a Konnektor
//! or TI-Gateway, or from the internet.
//!
//! This is the host's connectivity, not a product's protocol: the catalog spans every
//! product of an environment, and a judgement only tells whether the service answered as
//! itself rather than a gateway or a front page. None of them trusts what it reads; the
//! product clients verify the same documents in their flows.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use rustls::CertificateError;
use serde::{Deserialize, Serialize};
use ti_pki::ocsp::OcspChecker;
use ti_pki::tls::ServerCheck;
use ti_pki::{Env, Timestamp};
use ti_tls::TiVerifier;
use ureq::Agent;

use crate::client::Client;
use crate::error::Error;
use crate::net::{Net, builder};
use crate::trust::Session;

/// Every request is given up after this.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// The endpoints of each environment, unless the front end passes its own.
const ENDPOINTS: &str = include_str!("probe/endpoints.json");

/// A well-formed insurant ID (a letter and nine digits) that belongs to nobody: the
/// Information Service answers `noHealthRecord` for it.
const EPA_INSURANT: &str = "X000000000";

/// Largest body read; discovery documents and catalogs are a few KiB.
const MAX_BODY: u64 = 1024 * 1024;

/// A service of an environment and how it is checked.
#[derive(Clone, Debug, Deserialize)]
pub struct Endpoint {
    /// Its name, e.g. `idpd-ti`.
    pub name: String,
    /// How it is reached.
    pub access: Access,
    /// How it is checked.
    pub kind: Kind,
    /// Its URL, or `dns://ADDRESS` for a DNS server.
    pub url: String,
    /// The profile its certificate is verified under; `web` unless the data says `ti`.
    #[serde(default)]
    pub tls: TlsProfile,
}

impl Endpoint {
    /// The host (and port) of the URL.
    pub fn host(&self) -> String {
        host(&self.url)
    }
}

/// The profile of `spec/pki-validation` a server is verified under. Being a TI service
/// does not decide it: the IDP-Dienst and E-Rezept present public certificates, ePA and
/// KIM certificates of the TI's PKI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsProfile {
    /// The TI's private trust: the environment's TSL and roots.
    Ti,
    /// The operating system's roots, under the TI's rules for the internet.
    #[default]
    Web,
}

impl TlsProfile {
    /// `ti` or `web`.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsProfile::Ti => "ti",
            TlsProfile::Web => "web",
        }
    }
}

/// How an endpoint is reached; part of the endpoint data, never inferred from its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    /// Only through a Konnektor's or TI-Gateway's VPN.
    TiVpn,
    /// Directly.
    Internet,
    /// Through the TI VPN into a Bestandsnetz (gematik's Bestandsnetze.xml), which the
    /// Konnektor routes only when the practice has booked it.
    Bestandsnetz,
}

impl Access {
    /// Every access path, in the order a report shows them.
    pub const ALL: [Access; 3] = [Access::TiVpn, Access::Internet, Access::Bestandsnetz];

    /// Whether the services of this path are expected to answer. A practice need not
    /// book a Bestandsnetz, so not reaching one is a warning, not a failure.
    pub fn required(self) -> bool {
        self != Access::Bestandsnetz
    }
}

/// How an endpoint is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
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

/// What a probe found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The expected answer.
    Ok,
    /// An answer, but not the expected one.
    Warn,
    /// No answer.
    Fail,
}

/// Where an endpoint came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The endpoints of the environment.
    Builtin,
    /// An instance the catalog lists.
    Catalog,
}

/// The outcome of one probe.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// What it found.
    pub status: Status,
    /// The endpoint answered; false for a transport failure, whatever the status.
    pub answered: bool,
    /// In a few words.
    pub detail: String,
    /// The HTTP status of the answer.
    pub http_status: Option<u16>,
    /// From the request to the answer or the failure.
    pub duration: Duration,
    /// Endpoints a catalog lists.
    pub discovered: Vec<Endpoint>,
    /// Whether the server's certificate verified: `None` without a handshake.
    pub verified: Option<bool>,
}

/// An endpoint and, once probed, its outcome.
#[derive(Clone, Debug)]
pub struct Probe {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// Where it came from.
    pub source: Source,
    /// `None` while it runs.
    pub outcome: Option<Outcome>,
}

/// The endpoints of `env`: from `catalog`, a JSON object of endpoint lists by environment,
/// or the built-in one.
///
/// # Errors
///
/// [`Error::ProbeEndpoints`] for a catalog that is not such an object.
pub fn endpoints(catalog: Option<&str>, env: Env) -> Result<Vec<Endpoint>, Error> {
    let mut all: HashMap<String, Vec<Endpoint>> =
        serde_json::from_str(catalog.unwrap_or(ENDPOINTS))
            .map_err(|e| Error::ProbeEndpoints(e.to_string()))?;
    Ok(all.remove(env.as_str()).unwrap_or_default())
}

/// The HTTP settings with the probe's limits: [`TIMEOUT`] per request, OCSP included, no
/// retries. `-k` reaches every endpoint through an agent of its own ([`Agents::new`]).
fn limits(net: &Net) -> Net {
    Net {
        insecure: false,
        connect_timeout: TIMEOUT,
        max_time: TIMEOUT,
        retry: 0,
        ..net.clone()
    }
}

/// The agents the probes go through, one per profile. The `ti` one exists only when an
/// endpoint needs it and the environment's trust material loaded; otherwise why not.
pub struct Agents {
    web: Agent,
    /// With `-k`, the agent for every endpoint: no certificate is checked.
    unchecked: Option<Agent>,
    ti: Result<Agent, String>,
    /// The ePA `x-useragent`, `ClientId/Version`; the aggregators reject other shapes.
    epa_user_agent: String,
}

impl fmt::Debug for Agents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agents")
            .field("unchecked", &self.unchecked.is_some())
            .field("ti", &self.ti.as_ref().map(|_| "agent"))
            .finish_non_exhaustive()
    }
}

impl Agents {
    /// The agents for `endpoints` of `env`, with `client`'s proxy and user agent and the
    /// probe's limits. `web` trusts the operating system's roots, or the client's CA files.
    /// `ti` trusts `env`'s TSL and roots, loaded (from the cache while fresh) by the
    /// session `trust` opens before any probe starts, and asks the OCSP responders a
    /// stapled answer does not replace; when it cannot be made, its endpoints fail with
    /// the reason. With the client's `-k`, one agent that checks no certificate serves
    /// every endpoint and no trust material is loaded. `epa_user_agent` is the
    /// `ClientId/Version` the ePA Information Service is asked as.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for an unusable proxy or CA file or directory.
    pub fn new<E: From<Error> + fmt::Display>(
        client: &Client,
        env: Env,
        endpoints: &[Endpoint],
        trust: impl FnOnce() -> Result<Session, E>,
        epa_user_agent: &str,
    ) -> Result<Agents, Error> {
        let net = limits(client.net());
        let unchecked = if client.net().insecure {
            Some(crate::http::unchecked_agent(&net)?)
        } else {
            None
        };
        let web = crate::tls::agent(builder(&net, "https")?, crate::http::web_config(&net)?);
        let ti = if unchecked.is_none() && endpoints.iter().any(|e| e.tls == TlsProfile::Ti) {
            ti_agent(client, &net, env, trust).map_err(|error| error.to_string())
        } else {
            Err("no endpoint is verified under ti".into())
        };
        Ok(Agents {
            web,
            unchecked,
            ti,
            epa_user_agent: epa_user_agent.to_owned(),
        })
    }
}

/// The agent of the `ti` profile for `env`, its OCSP requests under the probe's limits.
fn ti_agent<E: From<Error>>(
    client: &Client,
    net: &Net,
    env: Env,
    trust: impl FnOnce() -> Result<Session, E>,
) -> Result<Agent, E> {
    // The trust material downloads with the session's own limits: a TSL is larger than an
    // answer the probe waits for.
    let session = trust()?;
    let (config, material) = session.load_env(env, false, None)?;
    if let Some(observer) = client.observer() {
        observer(format_args!(
            "{env}: {} roots, {} TSL CAs from {} for the ti profile",
            material.info.roots, material.info.intermediates, material.info.source
        ));
    }
    let mut ocsp = Client::new(net.clone());
    if let Some(observer) = client.observer() {
        ocsp = ocsp.observed(Arc::clone(observer));
    }
    let responder =
        OcspChecker::new(&config, ocsp.downloads()?, Timestamp::now).with_store(session.store());
    let check = ServerCheck::new(config, Some(material.store));
    let verifier = TiVerifier::new(check, responder);
    let config = Arc::new(ti_tls::client_config(Arc::new(verifier)));
    Ok(crate::tls::agent(builder(net, "https")?, config))
}

/// Probes `endpoints` of `env` in parallel through `agents`, and the instances a catalog
/// lists once it answered. `progress` is called on this thread with every probe so far,
/// each time one finished and at least every 100 ms while any runs, so that a front end
/// can draw them live. Returns the probes in the order they started and how long it took.
pub fn run(
    agents: Agents,
    env: Env,
    endpoints: Vec<Endpoint>,
    mut progress: impl FnMut(&[Probe]),
) -> (Vec<Probe>, Duration) {
    let agents = Arc::new(agents);
    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    let mut probes: Vec<Probe> = Vec::new();
    for endpoint in endpoints {
        spawn(&agents, env, &tx, probes.len(), &endpoint);
        probes.push(Probe {
            endpoint,
            source: Source::Builtin,
            outcome: None,
        });
    }
    while probes.iter().any(|p| p.outcome.is_none()) {
        if let Ok((index, outcome)) = rx.recv_timeout(Duration::from_millis(100)) {
            for endpoint in &outcome.discovered {
                let known = probes
                    .iter()
                    .any(|p| same_url(&p.endpoint.url, &endpoint.url));
                if !known {
                    spawn(&agents, env, &tx, probes.len(), endpoint);
                    probes.push(Probe {
                        endpoint: endpoint.clone(),
                        source: Source::Catalog,
                        outcome: None,
                    });
                }
            }
            probes[index].outcome = Some(outcome);
        }
        progress(&probes);
    }
    (probes, start.elapsed())
}

fn spawn(
    agents: &Arc<Agents>,
    env: Env,
    tx: &mpsc::Sender<(usize, Outcome)>,
    index: usize,
    endpoint: &Endpoint,
) {
    let (agents, tx, endpoint) = (Arc::clone(agents), tx.clone(), endpoint.clone());
    std::thread::spawn(move || {
        // The receiver outlives every worker; a send cannot fail while it runs.
        let _ = tx.send((index, probe(&agents, env, &endpoint)));
    });
}

/// Whether any endpoint reached by `access` answered: `None` while one is still
/// pending, or when there is none. The answer, not the status, counts: an unreachable
/// Bestandsnetz is a warning, yet the path is down.
pub fn available(probes: &[Probe], access: Access) -> Option<bool> {
    let group: Vec<&Probe> = probes
        .iter()
        .filter(|p| p.endpoint.access == access)
        .collect();
    if group.is_empty() {
        return None;
    }
    let mut outcomes = group.iter().map(|p| p.outcome.as_ref());
    if outcomes.clone().any(|o| o.is_none()) {
        return None;
    }
    Some(outcomes.any(|o| o.is_some_and(|o| o.answered)))
}

/// The result of a run, in the shape of `ti probe`'s JSON.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The environment.
    pub environment: &'static str,
    /// The whole run.
    pub duration_ms: u64,
    /// Probes by status.
    pub counts: Counts,
    /// Per access path, whether any of its endpoints answered.
    pub access_paths: Vec<AccessPath>,
    /// Every probe that finished.
    pub probes: Vec<ProbeInfo>,
}

/// An access path and whether it is up.
#[derive(Clone, Debug, Serialize)]
pub struct AccessPath {
    /// The path.
    pub access: Access,
    /// False when every endpoint reached this way failed: the path itself is down (for
    /// `ti-vpn`, no TI VPN), not the services.
    pub available: bool,
    /// Its probes.
    pub probes: usize,
}

/// Probes by status.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Counts {
    /// [`Status::Ok`].
    pub ok: usize,
    /// [`Status::Warn`].
    pub warn: usize,
    /// [`Status::Fail`].
    pub fail: usize,
}

/// One probe, finished.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeInfo {
    /// The endpoint's name.
    pub name: String,
    /// How it is reached.
    pub access: Access,
    /// How it was checked.
    pub kind: Kind,
    /// Its URL.
    pub url: String,
    /// The URL's host.
    pub host: String,
    /// `builtin`, or `catalog` for an instance the catalog lists.
    pub source: Source,
    /// What it found.
    pub status: Status,
    /// The endpoint answered; false for a transport failure.
    pub answered: bool,
    /// In a few words.
    pub detail: String,
    /// The HTTP status of the answer.
    pub http_status: Option<u16>,
    /// From the request to the answer or the failure.
    pub duration_ms: u64,
    /// `None` for an endpoint reached without TLS.
    pub tls: Option<TlsInfo>,
}

/// How a server's certificate fared.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TlsInfo {
    /// The profile it was verified under.
    pub profile: TlsProfile,
    /// True when the certificate verified, false when it was refused or the handshake
    /// failed, `None` when no handshake took place (no connection).
    pub verified: Option<bool>,
}

impl Report {
    /// The report of `probes` of `env`, which took `elapsed`.
    pub fn new(env: Env, probes: &[Probe], elapsed: Duration) -> Report {
        let infos: Vec<ProbeInfo> = probes
            .iter()
            .filter_map(|p| {
                let o = p.outcome.as_ref()?;
                Some(ProbeInfo {
                    name: p.endpoint.name.clone(),
                    access: p.endpoint.access,
                    kind: p.endpoint.kind,
                    url: p.endpoint.url.clone(),
                    host: p.endpoint.host(),
                    source: p.source,
                    status: o.status,
                    answered: o.answered,
                    detail: o.detail.clone(),
                    http_status: o.http_status,
                    duration_ms: millis(o.duration),
                    tls: p.endpoint.url.starts_with("https://").then_some(TlsInfo {
                        profile: p.endpoint.tls,
                        verified: o.verified,
                    }),
                })
            })
            .collect();
        let count = |s: Status| infos.iter().filter(|p| p.status == s).count();
        let access_paths = Access::ALL
            .into_iter()
            .filter_map(|access| {
                Some(AccessPath {
                    access,
                    available: available(probes, access)?,
                    probes: infos.iter().filter(|p| p.access == access).count(),
                })
            })
            .collect();
        Report {
            environment: env.as_str(),
            duration_ms: millis(elapsed),
            counts: Counts {
                ok: count(Status::Ok),
                warn: count(Status::Warn),
                fail: count(Status::Fail),
            },
            access_paths,
            probes: infos,
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Probes `endpoint` the way its kind asks for, over the agent of its profile.
fn probe(agents: &Agents, env: Env, endpoint: &Endpoint) -> Outcome {
    if endpoint.kind == Kind::Dns {
        return dns(endpoint);
    }
    let agent = match (endpoint.tls, &agents.ti) {
        _ if let Some(unchecked) = &agents.unchecked => unchecked,
        (TlsProfile::Web, _) => &agents.web,
        (TlsProfile::Ti, Ok(agent)) => agent,
        (TlsProfile::Ti, Err(reason)) => {
            return Outcome {
                status: Status::Fail,
                answered: false,
                detail: format!("TLS ti: no trust material: {reason}"),
                http_status: None,
                duration: Duration::ZERO,
                discovered: Vec::new(),
                verified: None,
            };
        }
    };
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
            .header("x-useragent", agents.epa_user_agent.as_str())
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
    let tls = url.starts_with("https://");
    let (status, body) = match answer {
        Ok(answer) => answer,
        // The server was reached; its certificate, or its TLS, is what failed.
        Err(error) if let Some(reason) = tls_failure(&error) => {
            return Outcome {
                status: Status::Fail,
                answered: true,
                detail: format!("TLS {}: {reason}", endpoint.tls.as_str()),
                http_status: None,
                duration,
                discovered: Vec::new(),
                verified: Some(false),
            };
        }
        Err(error) => {
            return Outcome {
                status: unanswered(endpoint.access),
                answered: false,
                detail: failure(&error),
                http_status: None,
                duration,
                discovered: Vec::new(),
                verified: None,
            };
        }
    };
    let (verdict, mut detail, discovered) = judge(endpoint.kind, env, base, status, &body);
    // The answer is judged as without -k; the detail and `tls.verified` say nobody checked
    // the certificate.
    let unchecked = tls && agents.unchecked.is_some();
    if unchecked {
        detail.push_str(" · TLS not checked (-k)");
    }
    Outcome {
        status: verdict,
        answered: true,
        detail,
        http_status: Some(status),
        duration,
        discovered,
        verified: (tls && !unchecked).then_some(true),
    }
}

/// Why the TLS of an answering server failed, in a few words; `None` for a failure before
/// a handshake. ureq's connector reports the handshake as an I/O error around rustls's.
fn tls_failure(error: &ureq::Error) -> Option<String> {
    let rustls = match error {
        ureq::Error::Rustls(error) => error,
        ureq::Error::Io(error) => error.get_ref()?.downcast_ref::<rustls::Error>()?,
        ureq::Error::Tls(reason) => return Some((*reason).to_owned()),
        _ => return None,
    };
    Some(match rustls {
        rustls::Error::InvalidCertificate(error) => refusal(error),
        rustls::Error::AlertReceived(alert) => format!("the server sent {alert:?}"),
        other => other.to_string(),
    })
}

/// A refused certificate: the profile's own verdict where rustls has no name for it.
fn refusal(error: &CertificateError) -> String {
    match error {
        CertificateError::UnknownIssuer => "unknown issuer".into(),
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            "certificate expired".into()
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "certificate not yet valid".into()
        }
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "certificate not issued for this host".into()
        }
        CertificateError::Revoked => "certificate revoked".into(),
        CertificateError::BadSignature => "bad signature".into(),
        CertificateError::Other(other) => match other.0.downcast_ref::<ti_tls::verifier::Refused>()
        {
            Some(refused) => refused.to_string(),
            None => other.to_string(),
        },
        other => other.to_string(),
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
    let connected = dns_server(&endpoint.host()).and_then(|server| {
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
        verified: None,
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
/// JWS whose payload is the JSON). Only its issuer is read, to tell the IDP from another
/// answer; its signature is the IDP-Dienst client's to verify.
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
            tls: TlsProfile::Web,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> HashMap<String, Vec<Endpoint>> {
        serde_json::from_str(ENDPOINTS).unwrap()
    }

    #[test]
    fn every_environment_has_valid_endpoints() {
        let all = all();
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
        let kebab = |name: &str| {
            !name.is_empty()
                && name.split('-').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
        };
        for (env, list) in &all() {
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
        let all = all();
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

    /// TASK-228: ePA presents certificates of the TI's PKI; every other endpoint, the
    /// IDP-Dienst and E-Rezept behind the TI VPN included, public ones.
    #[test]
    fn epa_is_verified_under_ti_every_other_endpoint_under_web() {
        for (env, list) in &all() {
            for e in list {
                let expected = if e.kind == Kind::Epa {
                    TlsProfile::Ti
                } else {
                    TlsProfile::Web
                };
                assert_eq!(e.tls, expected, "{env}: {}", e.name);
            }
        }
    }

    #[test]
    fn a_catalog_of_the_front_end_replaces_the_built_in_one() {
        let own =
            r#"{"dev": [{"name": "x", "access": "internet", "kind": "http", "url": "https://x"}]}"#;
        let list = endpoints(Some(own), Env::Dev).unwrap();
        assert_eq!(list.len(), 1);
        assert!(endpoints(Some(own), Env::Prod).unwrap().is_empty());
        assert!(matches!(
            endpoints(Some("{"), Env::Dev),
            Err(Error::ProbeEndpoints(_))
        ));
        assert!(endpoints(None, Env::Prod).unwrap().len() > 17);
    }

    fn handshake(error: rustls::Error) -> ureq::Error {
        ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    /// TASK-228: the reason a certificate was refused, rustls's name for it or the
    /// profile's verdict; a failure before any handshake is no TLS failure.
    #[test]
    fn a_refused_certificate_is_reported_with_its_reason() {
        let refused = |error| tls_failure(&handshake(rustls::Error::InvalidCertificate(error)));
        assert_eq!(
            refused(CertificateError::UnknownIssuer).as_deref(),
            Some("unknown issuer")
        );
        assert_eq!(
            refused(CertificateError::Revoked).as_deref(),
            Some("certificate revoked")
        );
        let verdict = ti_tls::Verdict {
            code: ti_tls::Code::SignatureAlgorithmNotAllowed,
            detail: "sha1WithRSAEncryption".into(),
            warnings: Vec::new(),
            reusable_until: None,
        };
        let other = rustls::OtherError(Arc::new(ti_tls::verifier::Refused(verdict)));
        assert_eq!(
            refused(CertificateError::Other(other)).as_deref(),
            Some("signature_algorithm_not_allowed: sha1WithRSAEncryption")
        );
        assert_eq!(tls_failure(&ureq::Error::ConnectionFailed), None);
        assert_eq!(
            tls_failure(&ureq::Error::Io(std::io::ErrorKind::TimedOut.into())),
            None
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
        let dev = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ti-cli/tests/fixtures/catalog-dev.json"
        ));
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

    /// A path is down only when none of its endpoints answered, and undecided while one
    /// still runs.
    #[test]
    fn a_path_is_down_when_none_of_its_endpoints_answered() {
        let endpoint = |name: &str, access| Endpoint {
            name: name.into(),
            access,
            kind: Kind::Http,
            url: format!("https://{name}"),
            tls: TlsProfile::Web,
        };
        let outcome = |answered| Outcome {
            status: if answered { Status::Ok } else { Status::Fail },
            answered,
            detail: String::new(),
            http_status: None,
            duration: Duration::ZERO,
            discovered: Vec::new(),
            verified: None,
        };
        let mut probes = vec![
            Probe {
                endpoint: endpoint("a", Access::TiVpn),
                source: Source::Builtin,
                outcome: Some(outcome(false)),
            },
            Probe {
                endpoint: endpoint("b", Access::TiVpn),
                source: Source::Builtin,
                outcome: None,
            },
        ];
        assert_eq!(available(&probes, Access::TiVpn), None);
        assert_eq!(available(&probes, Access::Internet), None);
        probes[1].outcome = Some(outcome(false));
        assert_eq!(available(&probes, Access::TiVpn), Some(false));
        probes[1].outcome = Some(outcome(true));
        assert_eq!(available(&probes, Access::TiVpn), Some(true));
    }
}
