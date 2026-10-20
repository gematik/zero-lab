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

//! `ti directory login owner|holder|service|ti-provider`: a FHIR-Directory access token
//! from one of its Auth-Service endpoints, by card through the IDP-Dienst, with a
//! TI-Messenger RegService-OpenID-Token, or with client credentials at the directory's
//! Keycloak.

use jwz::jwt::{Clock, SystemClock};
use serde::Serialize;
use ti_directory::owner;
use ti_directory::{AccessToken, Directory, Endpoint, Idp, TokenClaims, exchange};
use ti_idpd::Warning;
use ti_idpd::authenticator::{self, Authenticated};
use ti_pki::Timestamp;

use super::idp_trust::{CertificateInfo, IdpTrust, certificate_infos};
use super::idpd::certificate_lines;
use crate::block::block_on;
use crate::cli::{
    DirectoryClientArgs, DirectoryLoginCommand, DirectoryOwnerArgs, DirectoryTargetArgs, GlobalArgs,
};
use crate::error::{CliError, Exit};
use crate::http;
use crate::identity::Identity;
use crate::output::document::when;

use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document, one for every path.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// `owner`, `holder`, `service` or `ti-provider`.
    endpoint: &'static str,
    /// `card`, `regservice` or `client_credentials`.
    method: &'static str,
    /// The access token, for `Authorization: Bearer`.
    access_token: String,
    token_type: String,
    /// Seconds of validity, as announced.
    expires_in: u64,
    /// When it expires, seconds since the epoch, from the local clock and `expires_in`.
    expires_at: u64,
    /// The token's payload as decoded, not verified: the directory issued it over TLS.
    token: TokenClaims,
    directory: DirectoryInfo,
    /// The IDP-Dienst a card answered; null for the other methods.
    idp: Option<IdpInfo>,
    /// The card identity; null without one.
    identity: Option<IdentityInfo>,
    /// Claims of the IDP's challenge, for the record; `client_id` is the directory's.
    challenge: Option<ChallengeInfo>,
    /// The client ID of client credentials; null for the owner methods.
    client_id: Option<String>,
    /// What was not proven: `idp_certificates_unverified` with `--idp-unverified`.
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "the field names are the JSON contract"
)]
struct DirectoryInfo {
    base_url: String,
    /// The endpoint that issued the token.
    endpoint_url: String,
    /// The IDP-Dienst authorization URL the directory sent the card to; null without
    /// a card.
    authorization_url: Option<String>,
}

#[derive(Serialize)]
struct IdpInfo {
    base_url: String,
    issuer: String,
    /// The discovery document's and `PuK_IDP_SIG`'s certificates.
    certificates: Vec<CertificateInfo>,
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
}

/// Runs `ti directory login …`.
pub fn login(
    command: &DirectoryLoginCommand,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    match command {
        DirectoryLoginCommand::Owner(args) => login_owner(args, global, out),
        DirectoryLoginCommand::Holder(args) => login_client(args, Endpoint::Holder, global, out),
        DirectoryLoginCommand::Service(args) => login_client(args, Endpoint::Service, global, out),
        DirectoryLoginCommand::TiProvider(args) => {
            login_client(args, Endpoint::TiProvider, global, out)
        }
    }
}

/// What the directory needs to know for a method.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Needs {
    Idp,
    Keycloak,
    Nothing,
}

/// The directory of `--env`, or of `--url` with what `needs` asks for.
fn directory(target: &DirectoryTargetArgs, needs: Needs) -> Result<Directory, CliError> {
    if let Some(url) = &target.url {
        let idp = match (&target.idp_url, needs) {
            (Some(idp), _) => Idp::new(idp),
            (None, Needs::Idp) => {
                return Err(CliError::Arguments(
                    "a card login at --url needs the directory's IDP-Dienst: --idp-url".into(),
                ));
            }
            // Never contacted: only a card login goes to the IDP.
            (None, _) => Idp::new(url),
        };
        let mut directory = Directory::new(url, idp);
        match (&target.auth_url, needs) {
            (Some(auth), _) => directory = directory.with_auth_url(auth),
            (None, Needs::Keycloak) => {
                return Err(CliError::Arguments(
                    "client credentials at --url need the directory's Keycloak: --auth-url".into(),
                ));
            }
            (None, _) => {}
        }
        return Ok(directory);
    }
    match target.env.and_then(crate::cli::Environment::concrete) {
        Some(env) => Ok(Directory::for_env(env)),
        None => Err(CliError::Environment(
            "the FHIR-Directory is one environment's; auto has nothing to detect from".into(),
        )),
    }
}

/// A `ti_directory::Error` as the CLI reports it; IDP failures keep their own kinds.
fn directory_error(error: ti_directory::Error, trust: Option<&IdpTrust<'_>>) -> CliError {
    match error {
        ti_directory::Error::Idpd(inner) => trust
            .and_then(IdpTrust::take_error)
            .unwrap_or(CliError::Idpd(inner)),
        other => CliError::Directory(Box::new(other)),
    }
}

fn login_client(
    args: &DirectoryClientArgs,
    endpoint: Endpoint,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let directory = directory(&args.target, Needs::Keycloak)?;
    let secret = crate::input::first_line(&args.client_secret_path)?;
    let transport = http::Logged::new(&global.net, out)?;
    out.verbose(
        1,
        format_args!(
            "FHIR-Directory {} via Keycloak {}, realm {}",
            directory.base_url(),
            directory.auth_url().unwrap_or("-"),
            endpoint.realm().unwrap_or("-")
        ),
    );
    let token = exchange::login_client_credentials(
        &transport,
        &directory,
        endpoint,
        &args.client_id,
        &secret,
    )
    .map_err(|error| directory_error(error, None))?;
    let mut report = report(&directory, endpoint, "client_credentials", token);
    report.client_id = Some(args.client_id.clone());
    emit(&report, &args.target, out)
}

fn login_owner(
    args: &DirectoryOwnerArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    if let Some(path) = &args.regservice_token_path {
        let directory = directory(&args.target, Needs::Nothing)?;
        let bearer = crate::input::first_line(path)?;
        let transport = http::Logged::new(&global.net, out)?;
        let token = exchange::login_bearer(&transport, &directory, Endpoint::Owner, &bearer)
            .map_err(|error| directory_error(error, None))?;
        let report = report(&directory, Endpoint::Owner, "regservice", token);
        return emit(&report, &args.target, out);
    }
    let Some(identity_args) = &args.identity else {
        return Err(CliError::Arguments(
            "an owner login needs a card identity (--p12, --cert/--key, --card) or --regservice-token-path".into(),
        ));
    };
    let directory = directory(&args.target, Needs::Idp)?;
    let identity = Identity::load(identity_args, global, out)?;
    let signer = identity.signer(jwz_brainpool::BP256R1)?;
    let transport = http::Logged::new(&global.net, out)?;
    out.verbose(
        1,
        format_args!(
            "FHIR-Directory {} via IDP-Dienst {}",
            directory.base_url(),
            directory.idp().base_url()
        ),
    );
    let trust = IdpTrust::new(args.idp_unverified, args.target.env, global, out);
    let done = block_on(owner::login(
        &transport,
        &directory,
        &authenticator::Identity {
            signer: &*signer,
            certificate_der: identity.certificate.der(),
        },
        SystemClock.now(),
        &trust,
    ))
    .map_err(|error| directory_error(error, Some(&trust)))?;
    let mut report = report(&directory, Endpoint::Owner, "card", done.token);
    report.directory.authorization_url = Some(done.authorization_url);
    with_card(&mut report, &directory, &done.authenticated, &identity);
    emit(&report, &args.target, out)
}

fn report(
    directory: &Directory,
    endpoint: Endpoint,
    method: &'static str,
    token: AccessToken,
) -> Report {
    let now = SystemClock.now();
    Report {
        schema: SCHEMA,
        endpoint: endpoint.as_str(),
        method,
        expires_at: now.saturating_add(token.expires_in),
        access_token: token.access_token,
        token_type: token.token_type,
        expires_in: token.expires_in,
        token: token.claims,
        directory: DirectoryInfo {
            base_url: directory.base_url().to_owned(),
            endpoint_url: directory.endpoint_url(endpoint),
            authorization_url: None,
        },
        idp: None,
        identity: None,
        challenge: None,
        client_id: None,
        warnings: Vec::new(),
    }
}

/// The card's part of the report: IDP, identity, challenge, warnings.
fn with_card(
    report: &mut Report,
    directory: &Directory,
    authenticated: &Authenticated,
    identity: &Identity,
) {
    let claim = |name: &str| {
        authenticated
            .challenge_claims
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    report.idp = Some(IdpInfo {
        base_url: directory.idp().base_url().to_owned(),
        issuer: authenticated.discovery.metadata.issuer.clone(),
        certificates: certificate_infos(&authenticated.certificates),
    });
    report.identity = Some(IdentityInfo {
        subject: identity.certificate.subject().to_string(),
        telematik_id: identity.telematik_id(),
    });
    report.challenge = Some(ChallengeInfo {
        client_id: claim("client_id"),
        scope: claim("scope"),
    });
    report.warnings = authenticated
        .warnings
        .iter()
        .map(|w| Warning::as_str(*w))
        .collect();
}

fn emit(report: &Report, target: &DirectoryTargetArgs, out: &Output) -> Result<Exit, CliError> {
    if target.token {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", report.access_token)?;
        return Ok(Exit::Ok);
    }
    if out.is_json() {
        out.json(report)?;
    } else {
        out.render(&document(report))?;
    }
    Ok(Exit::Ok)
}

/// The text view.
fn document(report: &Report) -> Document {
    let mut doc = Document::default();
    doc.field(
        "authenticated",
        Line::status(Tone::Good, format!("{} token received", report.endpoint))
            .and_dim(format!(" · {}", report.method.replace('_', " "))),
    );
    doc.field("endpoint", Line::link(&report.directory.endpoint_url));
    if let Some(idp) = &report.idp {
        doc.field("IDP", Line::text(&idp.issuer));
        certificate_lines(&mut doc, &idp.certificates);
    }
    if let Some(identity) = &report.identity {
        doc.field("identity", Line::text(&identity.subject));
        if let Some(id) = &identity.telematik_id {
            doc.field("Telematik-ID", Line::code(id));
        }
    }
    if let Some(client) = &report.client_id {
        doc.field("client", Line::code(client));
    }
    let shown_id = report
        .identity
        .as_ref()
        .and_then(|i| i.telematik_id.as_ref())
        .or(report.client_id.as_ref());
    if let Some(sub) = &report.token.sub
        && Some(sub) != shown_id
    {
        doc.field("subject", Line::code(sub));
    }
    if let Some(scope) = &report.token.scope {
        doc.field("scope", Line::text(scope));
    }
    doc.field(
        "expires",
        Line::text(format!(
            "{} ({} h)",
            when(Timestamp(report.expires_at)),
            report.expires_in / 3600
        )),
    );
    doc.field("token", Line::code(&report.access_token));
    for warning in &report.warnings {
        doc.field("warning", Line::status(Tone::Warn, *warning));
    }
    doc
}
