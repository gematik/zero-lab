//! `ti idpd authenticate`: the IDP-Dienst's Authenticator-Modul flow with an identity,
//! from an authorization URL to the authorization code. What an ePA client does for
//! `send_authorization_request_sc` → `send_authcode_sc`.

use jwz::jwt::{Clock, SystemClock};
use serde::Serialize;
use ti_idpd::authenticator;
use ti_idpd::http::{Request, Response, Transport, TransportError};
use ti_idpd::ureq::UreqTransport;
use ti_idpd::{Idp, Warning};

use crate::cli::{GlobalArgs, IdpdAuthenticateArgs};
use crate::error::{CliError, Exit};
use crate::http;
use crate::identity::Identity;
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The authorization code for the relying party.
    code: String,
    /// The `state` the relying party sent, if any.
    state: Option<String>,
    /// The redirect the IDP answered with, as sent.
    redirect_url: String,
    idp: IdpInfo,
    identity: IdentityInfo,
    /// Claims of the challenge, for the record.
    challenge: ChallengeInfo,
    /// What was not proven: `idp_certificates_unverified` until the IDP's certificates
    /// are checked against the TSL.
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct IdpInfo {
    base_url: String,
    issuer: String,
    authorization_endpoint: String,
}

#[derive(Serialize)]
struct IdentityInfo {
    subject: String,
    telematik_id: Option<String>,
}

#[derive(Serialize)]
struct ChallengeInfo {
    client_id: Option<String>,
    scope: Option<String>,
    redirect_uri: Option<String>,
}

/// Runs `ti idpd authenticate`.
pub fn authenticate(
    args: &IdpdAuthenticateArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let idp = match (&args.idp_url, args.env) {
        (Some(url), _) => Idp::new(url),
        (None, Some(env)) => Idp::for_env(env.concrete().ok_or_else(|| {
            CliError::Environment(
                "the IDP-Dienst is one environment's; auto has nothing to detect from".into(),
            )
        })?),
        // clap: one of the two is required.
        (None, None) => return Err(CliError::Environment("--env or --idp-url".into())),
    };
    let identity = Identity::load(&args.identity, global, out)?;
    let signer = identity.signer(jwz_brainpool::BP256R1)?;
    let transport = Logged {
        inner: UreqTransport::new(http::idp_agent(&global.net)?),
        out,
    };
    out.verbose(1, format_args!("IDP-Dienst {}", idp.base_url()));
    let done = authenticator::authenticate(
        &transport,
        &idp,
        &authenticator::Identity {
            signer: &*signer,
            certificate_der: identity.certificate.der(),
        },
        &args.auth_url,
        SystemClock.now(),
    )
    .map_err(CliError::Idpd)?;
    let claim = |name: &str| {
        done.challenge_claims
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    let report = Report {
        schema: SCHEMA,
        code: done.redirect.code,
        state: done.redirect.state,
        redirect_url: done.redirect.url,
        idp: IdpInfo {
            base_url: idp.base_url().to_owned(),
            issuer: done.discovery.metadata.issuer,
            authorization_endpoint: done.discovery.metadata.authorization_endpoint,
        },
        identity: IdentityInfo {
            subject: identity.certificate.subject().to_string(),
            telematik_id: identity.telematik_id(),
        },
        challenge: ChallengeInfo {
            client_id: claim("client_id"),
            scope: claim("scope"),
            redirect_uri: claim("redirect_uri"),
        },
        warnings: done.warnings.iter().map(|w| Warning::as_str(*w)).collect(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.field("authenticated", Line::status(Tone::Good, "code received"));
    doc.field("IDP", Line::text(&report.idp.issuer));
    doc.field(
        "client",
        Line::text(report.challenge.client_id.as_deref().unwrap_or("-")),
    );
    doc.field("identity", Line::text(&report.identity.subject));
    if let Some(id) = &report.identity.telematik_id {
        doc.field("Telematik-ID", Line::code(id));
    }
    doc.field("code", Line::code(&report.code));
    if let Some(state) = &report.state {
        doc.field("state", Line::code(state));
    }
    doc.field("redirect", Line::link(&report.redirect_url));
    for warning in &report.warnings {
        doc.field("warning", Line::status(Tone::Warn, *warning));
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// The transport with one `-v` line per request.
struct Logged<'a> {
    inner: UreqTransport,
    out: &'a Output,
}

impl Transport for Logged<'_> {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let response = self.inner.send(request);
        match &response {
            Ok(r) => self.out.verbose(
                1,
                format_args!(
                    "{} {} → {} ({} bytes)",
                    request.method,
                    request.url,
                    r.status,
                    r.body.len()
                ),
            ),
            Err(e) => self
                .out
                .verbose(1, format_args!("{} {} → {e}", request.method, request.url)),
        }
        response
    }
}
