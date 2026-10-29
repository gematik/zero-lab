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

//! The checks of a `.kon` configuration, step by step from the file to the cards, as
//! pure functions of what the host observed: the host reads the file, connects and
//! calls; these functions judge. One [`Report`] for every front end.
//!
//! The steps, in order: [`StepId::File`], [`StepId::Tcp`], [`StepId::Tls`],
//! [`StepId::Auth`], [`StepId::Sds`], [`StepId::Context`], [`StepId::Cards`]. A step
//! that fails ends the run; the steps after it are skipped.
//!
//! The service directory is read over https only: an `http` url fails. In the
//! production environment (`env: pu`), `insecureSkipVerify` and credentials of type
//! `none` fail; elsewhere they are warnings. The parser accepts them everywhere.

use serde::Serialize;
use ti_pki::Certificate;
use ti_types::{Env, Timestamp};

use crate::config::{CertificateView, ClientCertificate, ConfigView};
use crate::dotkon::{Credentials, Dotkon, DotkonError};
use crate::error::Error;
use crate::sds::ServiceDirectory;
use crate::types::Card;

/// How a step or a finding came out; ordered from best to worst.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// As it should be.
    #[default]
    Ok,
    /// Not run, because an earlier step failed or the host could not observe it.
    Skip,
    /// Works, but should be changed.
    Warn,
    /// Does not work, or is not allowed.
    Fail,
}

/// The steps of a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepId {
    /// The `.kon` file: readable, valid, its mode and secrets, `https`.
    File,
    /// Name resolution and the TCP connection.
    Tcp,
    /// The Konnektor's TLS certificate against the pin, CA or `insecureSkipVerify`.
    Tls,
    /// The client authentication: basic, the PKCS#12 client certificate, or none.
    Auth,
    /// The service directory `connector.sds`: product and service versions.
    Sds,
    /// The call context (Mandant, client system, workplace), with GetCards.
    Context,
    /// The cards in the Konnektor's terminals.
    Cards,
}

impl StepId {
    /// Every step, in the order they run.
    pub const ALL: [StepId; 7] = [
        StepId::File,
        StepId::Tcp,
        StepId::Tls,
        StepId::Auth,
        StepId::Sds,
        StepId::Context,
        StepId::Cards,
    ];

    /// The lowercase name, as in JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            StepId::File => "file",
            StepId::Tcp => "tcp",
            StepId::Tls => "tls",
            StepId::Auth => "auth",
            StepId::Sds => "sds",
            StepId::Context => "context",
            StepId::Cards => "cards",
        }
    }
}

/// One observation of a step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// How it came out.
    pub status: Status,
    /// What was found.
    pub message: String,
    /// What to do about it.
    pub hint: Option<String>,
    /// What a front end can offer to do about it: `renew_pin` (fetch the server
    /// certificate, show it next to the pinned one, replace the pin once confirmed).
    pub action: Option<&'static str>,
}

impl Finding {
    /// A finding with `hint`.
    pub fn new(status: Status, message: impl Into<String>, hint: Option<&str>) -> Self {
        Finding {
            status,
            message: message.into(),
            hint: hint.map(str::to_owned),
            action: None,
        }
    }

    /// The finding with `action` for a front end to offer.
    #[must_use]
    pub fn with_action(mut self, action: &'static str) -> Self {
        self.action = Some(action);
        self
    }

    /// An `ok` finding.
    pub fn ok(message: impl Into<String>) -> Self {
        Finding::new(Status::Ok, message, None)
    }
}

/// One step with its findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Which step.
    pub id: StepId,
    /// The worst status of its findings.
    pub status: Status,
    /// What it found; at least one.
    pub findings: Vec<Finding>,
}

impl Step {
    /// The step with `findings`, its status the worst of theirs.
    pub fn new(id: StepId, findings: Vec<Finding>) -> Self {
        let status = findings
            .iter()
            .map(|f| f.status)
            .max()
            .unwrap_or(Status::Skip);
        Step {
            id,
            status,
            findings,
        }
    }

    /// A step that did not run, and why.
    pub fn skipped(id: StepId, why: impl Into<String>) -> Self {
        Step::new(id, vec![Finding::new(Status::Skip, why, None)])
    }
}

/// The steps of a check, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// `fail` if a step failed, else `warn` if one warned, else `ok`; set by
    /// [`finish`](Self::finish).
    pub status: Status,
    /// The steps run so far.
    pub steps: Vec<Step>,
}

impl Report {
    /// Adds `step`; returns whether the next one should run (the step did not fail).
    pub fn push(&mut self, step: Step) -> bool {
        let failed = step.status == Status::Fail;
        self.steps.push(step);
        !failed
    }

    /// Completes the report: every step not run is skipped, and the status is set.
    #[must_use]
    pub fn finish(mut self) -> Self {
        let failed = self
            .steps
            .iter()
            .find(|s| s.status == Status::Fail)
            .map(|s| s.id);
        for id in StepId::ALL {
            if !self.steps.iter().any(|s| s.id == id) {
                let why = failed.map_or_else(
                    || "not run".to_owned(),
                    |f| format!("skipped: the {} step failed", f.as_str()),
                );
                self.steps.push(Step::skipped(id, why));
            }
        }
        self.steps
            .sort_by_key(|s| StepId::ALL.iter().position(|id| *id == s.id));
        let worst = self
            .steps
            .iter()
            .map(|s| s.status)
            .filter(|s| *s != Status::Skip)
            .max()
            .unwrap_or(Status::Ok);
        self.status = worst;
        self
    }
}

/// Whether the Konnektor is reached over TLS.
pub fn is_https(dotkon: &Dotkon) -> bool {
    dotkon.url.starts_with("https://")
}

/// Whether the file is for the production environment.
fn production(dotkon: &Dotkon) -> bool {
    dotkon.env.is_some_and(Env::is_prod)
}

// ---- file ---------------------------------------------------------------------------

/// The `.kon` file: `parsed` is [`Dotkon::parse`] of `json`; `mode` the Unix permission
/// bits, `None` where the host has none.
pub fn file(parsed: &Result<Dotkon, DotkonError>, json: &[u8], mode: Option<u32>) -> Step {
    let dotkon = match parsed {
        Ok(dotkon) => dotkon,
        Err(e) => {
            return Step::new(
                StepId::File,
                vec![Finding::new(
                    Status::Fail,
                    format!("invalid: {}", e.problems.join("; ")),
                    Some(
                        "correct the fields named; `config show` shows the file without its secrets",
                    ),
                )],
            );
        }
    };
    let mut findings = vec![Finding::ok("valid .kon configuration")];
    match mode {
        Some(mode) if mode & 0o077 != 0 => findings.push(Finding::new(
            Status::Warn,
            format!("mode {:04o}: others may read the file", mode & 0o7777),
            Some("chmod 600 the file: a .kon file holds the Konnektor's credentials"),
        )),
        Some(mode) => findings.push(Finding::ok(format!("mode {:04o}", mode & 0o7777))),
        None => findings.push(Finding::new(
            Status::Skip,
            "file mode not checked on this platform",
            None,
        )),
    }
    let view = ConfigView::new(dotkon, json);
    let plain = view.plain_secrets();
    if !plain.is_empty() {
        findings.push(Finding::new(
            Status::Warn,
            format!("in plain text: {}", plain.join(", ")),
            Some("the .kon file is a secret itself: mode 0600, never shared or committed"),
        ));
    }
    if !dotkon.variables.is_empty() {
        findings.push(Finding::ok(format!(
            "from the environment: {}",
            dotkon.variables.join(", ")
        )));
    }
    if !is_https(dotkon) {
        findings.push(Finding::new(
            Status::Fail,
            format!("url {} is not https", dotkon.url),
            Some("the service directory is read over https only; change url to https://"),
        ));
    }
    Step::new(StepId::File, findings)
}

// ---- tcp ----------------------------------------------------------------------------

/// What the host saw when it connected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpObservation {
    /// `host:port` it connected to.
    pub target: String,
    /// The address connected to, or why it failed.
    pub result: Result<String, TcpFailure>,
}

/// Why a TCP connection failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpFailure {
    /// The host name does not resolve.
    Resolve(String),
    /// Nothing listens on the port.
    Refused(String),
    /// No answer in time.
    Timeout(String),
    /// Anything else.
    Other(String),
}

/// The TCP connection.
pub fn tcp(observation: &TcpObservation) -> Step {
    let target = &observation.target;
    let finding = match &observation.result {
        Ok(address) => Finding::ok(format!("connected to {target} ({address})")),
        Err(TcpFailure::Resolve(e)) => Finding::new(
            Status::Fail,
            format!("{target}: the name does not resolve: {e}"),
            Some("check the host in url and the DNS of this machine"),
        ),
        Err(TcpFailure::Refused(e)) => Finding::new(
            Status::Fail,
            format!("{target}: connection refused: {e}"),
            Some("check the port in url and that the Konnektor's web service interface is enabled"),
        ),
        Err(TcpFailure::Timeout(e)) => Finding::new(
            Status::Fail,
            format!("{target}: no answer: {e}"),
            Some(
                "check the host in url, the network path and firewalls; the Konnektor is in the local network",
            ),
        ),
        Err(TcpFailure::Other(e)) => Finding::new(
            Status::Fail,
            format!("{target}: {e}"),
            Some("check the host and port in url and the network"),
        ),
    };
    Step::new(StepId::Tcp, vec![finding])
}

// ---- tls ----------------------------------------------------------------------------

/// What the host saw in the TLS handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsObservation {
    /// The certificates the server sent, its own first; empty if it sent none.
    pub chain: Vec<Vec<u8>>,
    /// Whether the `.kon` trust (pin, CA, `insecureSkipVerify`) accepted the server
    /// certificate, or why not; `None` if the handshake ended before the check.
    pub verified: Option<Result<(), String>>,
    /// Whether the handshake completed, or why not.
    pub handshake: Result<(), String>,
}

impl TlsObservation {
    /// Whether the handshake failed only after the server certificate was accepted:
    /// the server refused the client, which the [`StepId::Auth`] step reports.
    pub fn client_refused(&self) -> bool {
        matches!(self.verified, Some(Ok(()))) && self.handshake.is_err()
    }
}

/// The Konnektor's TLS certificate, judged against the `.kon` trust at `now`.
pub fn tls(dotkon: &Dotkon, observation: &TlsObservation, now: Timestamp) -> Step {
    let mut findings = Vec::new();
    let Some(leaf_der) = observation.chain.first() else {
        let why = observation.handshake.clone().err().unwrap_or_default();
        return Step::new(
            StepId::Tls,
            vec![Finding::new(
                Status::Fail,
                format!("no server certificate received: {why}"),
                Some("check that url names the Konnektor's TLS port (https)"),
            )],
        );
    };
    let leaf = Certificate::from_der(leaf_der).ok();
    let leaf_view = leaf.as_ref().map(CertificateView::of);
    let sha256 = crate::config::sha256(leaf_der);
    findings.push(Finding::ok(match &leaf_view {
        Some(v) => format!(
            "server certificate {} (until {}), SHA-256 {sha256}",
            v.subject, v.not_after
        ),
        None => format!("server certificate SHA-256 {sha256} (does not parse)"),
    }));
    if let Some(view) = &leaf_view
        && view.expires < now
    {
        findings.push(Finding::new(
            Status::Warn,
            format!("the server certificate expired on {}", view.not_after),
            Some("the Konnektor's administrator renews its TLS certificate"),
        ));
    }
    let pins: Vec<&Vec<u8>> = dotkon
        .trust_store
        .iter()
        .filter(|der| !Certificate::from_der(der).is_ok_and(|c| c.is_ca()))
        .collect();
    let cas = dotkon.trust_store.len() - pins.len();
    let pinned = pins.contains(&leaf_der);
    if dotkon.insecure_skip_verify {
        findings.push(if production(dotkon) {
            Finding::new(
                Status::Fail,
                "insecureSkipVerify is not allowed in the production environment (env pu)",
                Some("remove insecureSkipVerify and pin the Konnektor's certificate in trustStore"),
            )
        } else {
            Finding::new(
                Status::Warn,
                "insecureSkipVerify: any server certificate is accepted",
                Some("pin the Konnektor's certificate in trustStore instead"),
            )
        });
    } else if pinned {
        findings.push(Finding::ok("matches the pinned certificate"));
    } else if !pins.is_empty() {
        let pinned: Vec<String> = pins.iter().map(|p| crate::config::sha256(p)).collect();
        findings.push(Finding::new(
            Status::Fail,
            format!(
                "the server certificate is not the pinned one (pinned SHA-256 {})",
                pinned.join(", ")
            ),
            Some("the Konnektor presents another certificate; compare its SHA-256 with the one the Konnektor's management shows, and if it was renewed on purpose, renew the pin"),
        ).with_action("renew_pin"));
    } else {
        match &observation.verified {
            Some(Ok(())) if cas > 0 => {
                findings.push(Finding::ok("issued by a CA of the trustStore"));
            }
            Some(Ok(())) => findings.push(Finding::new(
                Status::Warn,
                "no pin: checked against the operating system's trust store",
                Some("pin the Konnektor's certificate in trustStore"),
            )),
            Some(Err(e)) => findings.push(Finding::new(
                Status::Fail,
                format!("the server certificate is not trusted: {e}"),
                Some(if cas > 0 {
                    "the certificate must chain to a CA of the trustStore and name the host of url or expectedHost"
                } else {
                    "pin the Konnektor's certificate in trustStore"
                }),
            )),
            None => {}
        }
    }
    if observation.verified.is_none()
        && let Err(e) = &observation.handshake
    {
        findings.push(Finding::new(
            Status::Fail,
            format!("handshake failed: {e}"),
            Some("check that url names the Konnektor's TLS port"),
        ));
    }
    Step::new(StepId::Tls, findings)
}

// ---- auth ---------------------------------------------------------------------------

/// The client authentication: the credentials themselves (`client` is the PKCS#12
/// client certificate, [`crate::config::client_certificate`]), and how the Konnektor
/// took them: in the TLS handshake (`tls`) and when asked for the service directory
/// (`sds`).
pub fn auth(
    dotkon: &Dotkon,
    client: Option<&ClientCertificate>,
    tls: Option<&TlsObservation>,
    sds: Option<&Result<ServiceDirectory, Error>>,
    now: Timestamp,
) -> Step {
    let mut findings = Vec::new();
    match &dotkon.credentials {
        Credentials::Basic { username, .. } => {
            findings.push(Finding::ok(format!("basic authentication as {username}")));
        }
        Credentials::Pkcs12 { .. } => {
            if let Some(client) = client {
                client_certificate(client, now, &mut findings);
            }
        }
        Credentials::None => findings.push(if production(dotkon) {
            Finding::new(
                Status::Fail,
                "credentials of type none are not allowed in the production environment (env pu)",
                Some("authenticate the client system with basic or pkcs12 credentials"),
            )
        } else {
            Finding::new(
                Status::Warn,
                "no client authentication (credentials type none)",
                Some("a Konnektor should authenticate its client systems: basic or pkcs12"),
            )
        }),
    }
    let in_handshake = "the Konnektor refused the client in the TLS handshake";
    let refusal = match sds {
        _ if tls.is_some_and(TlsObservation::client_refused) => Some(in_handshake.to_owned()),
        Some(Err(Error::HttpStatus {
            status: status @ (401 | 403),
            ..
        })) => Some(format!("the Konnektor refused the client: HTTP {status}")),
        Some(Err(Error::Transport(e))) if e.message.contains("alert") => {
            Some(format!("{in_handshake}: {}", e.message))
        }
        _ => None,
    };
    if let Some(what) = refusal {
        let hint = match dotkon.credentials {
            Credentials::Basic { .. } => {
                "check username and password against the client system's settings in the Konnektor"
            }
            Credentials::Pkcs12 { .. } => {
                "the Konnektor's administrator assigns this client certificate to the client system"
            }
            Credentials::None => {
                "the Konnektor authenticates its client systems: use basic or pkcs12 credentials"
            }
        };
        findings.push(Finding::new(Status::Fail, what, Some(hint)));
    } else if sds.is_some_and(Result::is_ok) {
        findings.push(Finding::ok("accepted by the Konnektor"));
    }
    Step::new(StepId::Auth, findings)
}

fn client_certificate(client: &ClientCertificate, now: Timestamp, findings: &mut Vec<Finding>) {
    if let Some(error) = &client.error {
        findings.push(Finding::new(
            Status::Fail,
            error.clone(),
            Some("credentials.data holds the PKCS#12 file as base64, credentials.password its password"),
        ));
        return;
    }
    if let Some(cert) = &client.certificate {
        findings.push(Finding::ok(format!(
            "client certificate {} (until {}), {}",
            cert.subject,
            cert.not_after,
            client.key.as_deref().unwrap_or("unknown key")
        )));
        if cert.expires < now {
            findings.push(Finding::new(
                Status::Fail,
                format!("the client certificate expired on {}", cert.not_after),
                Some("export a new client certificate from the Konnektor's management"),
            ));
        }
    }
    if !client.key_usable {
        findings.push(Finding::new(
            Status::Fail,
            format!(
                "the TLS stack cannot sign with {}",
                client.key.as_deref().unwrap_or("this key")
            ),
            Some("use a client certificate with an RSA, P-256 or P-384 key"),
        ));
    }
    if client.pairs > 1 {
        findings.push(Finding::new(
            Status::Warn,
            format!(
                "{} certificates with their key; the first is used",
                client.pairs
            ),
            Some("keep only the client certificate of this client system in the file"),
        ));
    }
    if client.legacy_encryption() {
        findings.push(Finding::new(
            Status::Warn,
            format!("legacy encryption: {}", client.encryption.join(", ")),
            Some("`pki pkcs12 convert` writes the file with PBES2 AES-256-CBC"),
        ));
    }
}

// ---- sds ----------------------------------------------------------------------------

/// The service directory: the product, and each service this client speaks.
pub fn sds(result: &Result<ServiceDirectory, Error>) -> Step {
    let directory = match result {
        Ok(directory) => directory,
        Err(e) => {
            return Step::new(
                StepId::Sds,
                vec![Finding::new(
                    Status::Fail,
                    format!("connector.sds: {e}"),
                    Some("check url: the service directory is connector.sds below it"),
                )],
            );
        }
    };
    let p = &directory.product;
    let name = p.product_name.as_deref().unwrap_or(&p.product_code);
    let vendor = p.vendor_name.as_deref().unwrap_or(&p.vendor_id);
    let mut findings = vec![Finding::ok(format!(
        "{vendor} {name}, {} {}, firmware {}",
        p.product_type, p.product_type_version, p.fw_version
    ))];
    let mut offered = Vec::new();
    for (service, versions) in crate::BINDINGS {
        match directory.resolve(service, versions) {
            Ok(binding) => offered.push(format!("{service} {}", binding.version)),
            Err(e) => findings.push(Finding::new(
                Status::Warn,
                e.to_string(),
                Some("the commands that need this service will fail"),
            )),
        }
    }
    if !offered.is_empty() {
        findings.push(Finding::ok(offered.join(", ")));
    }
    Step::new(StepId::Sds, findings)
}

// ---- context and cards --------------------------------------------------------------

/// The call context, from the answer to GetCards.
pub fn context(dotkon: &Dotkon, result: &Result<Vec<Card>, Error>) -> Step {
    let context = format!(
        "mandantId {}, clientSystemId {}, workplaceId {}",
        dotkon.mandant_id, dotkon.client_system_id, dotkon.workplace_id
    );
    let finding =
        match result {
            Ok(_) => Finding::ok(format!("accepted: {context}")),
            Err(Error::Fault(fault)) => Finding::new(
                Status::Fail,
                format!("{fault} with {context}"),
                Some(fault.hint().unwrap_or(
                    "the Konnektor refused the call context; its code and text say why",
                )),
            ),
            Err(e) => Finding::new(
                Status::Fail,
                format!("GetCards: {e}"),
                Some("the Konnektor did not answer the call; -v shows it"),
            ),
        };
    Step::new(StepId::Context, vec![finding])
}

/// The cards the Konnektor lists for the call context.
pub fn cards(cards: &[Card]) -> Step {
    if cards.is_empty() {
        return Step::new(
            StepId::Cards,
            vec![Finding::new(
                Status::Warn,
                "no cards",
                Some("insert a card, or check that the terminals are assigned to the workplace"),
            )],
        );
    }
    let list: Vec<String> = cards
        .iter()
        .map(|c| match &c.iccsn {
            Some(iccsn) => format!("{} {iccsn}", c.card_type.as_str()),
            None => c.card_type.as_str().to_owned(),
        })
        .collect();
    Step::new(
        StepId::Cards,
        vec![Finding::ok(format!(
            "{} card{}: {}",
            cards.len(),
            if cards.len() == 1 { "" } else { "s" },
            list.join(", ")
        ))],
    )
}
