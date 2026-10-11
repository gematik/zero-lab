//! `ti directory login`: the FHIR-Directory's owner authentication with an identity,
//! from `GET /owner-authenticate` through the IDP-Dienst to the owner access token.

use jwz::jwt::{Clock, SystemClock};
use serde::Serialize;
use ti_directory::owner::{self, TokenClaims};
use ti_directory::{Directory, Idp};
use ti_idpd::{Warning, authenticator};
use ti_pki::Timestamp;

use super::idp_trust::{CertificateInfo, IdpTrust, certificate_infos};
use super::idpd::certificate_lines;
use crate::cli::{DirectoryLoginArgs, GlobalArgs};
use crate::error::{CliError, Exit};
use crate::http;
use crate::identity::Identity;
use crate::output::document::when;
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The owner access token, for `Authorization: Bearer`.
    access_token: String,
    token_type: String,
    /// Seconds of validity, as announced.
    expires_in: u64,
    /// When it expires, seconds since the epoch, from the local clock and `expires_in`.
    expires_at: u64,
    /// The token's payload as decoded, not verified: the directory issued it over TLS.
    token: TokenClaims,
    directory: DirectoryInfo,
    idp: IdpInfo,
    identity: IdentityInfo,
    /// Claims of the IDP's challenge, for the record; `client_id` is the directory's.
    challenge: ChallengeInfo,
    /// What was not proven: `idp_certificates_unverified` with `--idp-unverified`.
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct DirectoryInfo {
    base_url: String,
    /// The IDP-Dienst authorization URL the directory redirected to.
    authorization_url: String,
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

/// Runs `ti directory login`.
pub fn login(
    args: &DirectoryLoginArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let directory = match (&args.url, &args.idp_url, args.env) {
        (Some(url), Some(idp_url), _) => Directory::new(url, Idp::new(idp_url)),
        (None, None, Some(env)) => Directory::for_env(env.concrete().ok_or_else(|| {
            CliError::Environment(
                "the FHIR-Directory is one environment's; auto has nothing to detect from".into(),
            )
        })?),
        // clap: --env, or --url with --idp-url.
        _ => {
            return Err(CliError::Environment(
                "--env, or --url with --idp-url".into(),
            ));
        }
    };
    let identity = Identity::load(&args.identity, global, out)?;
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
    let trust = IdpTrust::new(args.idp_unverified, args.env, global, out);
    let now = SystemClock.now();
    let done = owner::login(
        &transport,
        &directory,
        &authenticator::Identity {
            signer: &*signer,
            certificate_der: identity.certificate.der(),
        },
        now,
        &trust,
    )
    .map_err(|error| match error {
        ti_directory::Error::Idpd(inner) => trust.take_error().unwrap_or(CliError::Idpd(inner)),
        other => CliError::Directory(Box::new(other)),
    })?;
    let claim = |name: &str| {
        done.authenticated
            .challenge_claims
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    let report = Report {
        schema: SCHEMA,
        expires_at: now.saturating_add(done.token.expires_in),
        access_token: done.token.access_token,
        token_type: done.token.token_type,
        expires_in: done.token.expires_in,
        token: done.token.claims,
        directory: DirectoryInfo {
            base_url: directory.base_url().to_owned(),
            authorization_url: done.authorization_url,
        },
        idp: IdpInfo {
            base_url: directory.idp().base_url().to_owned(),
            issuer: done.authenticated.discovery.metadata.issuer,
            certificates: certificate_infos(&done.authenticated.certificates),
        },
        identity: IdentityInfo {
            subject: identity.certificate.subject().to_string(),
            telematik_id: identity.telematik_id(),
        },
        challenge: ChallengeInfo {
            client_id: claim("client_id"),
            scope: claim("scope"),
        },
        warnings: done
            .authenticated
            .warnings
            .iter()
            .map(|w| Warning::as_str(*w))
            .collect(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    out.render(&document(&report))?;
    Ok(Exit::Ok)
}

/// The text view.
fn document(report: &Report) -> Document {
    let mut doc = Document::default();
    doc.field(
        "authenticated",
        Line::status(Tone::Good, "owner access token received"),
    );
    doc.field("directory", Line::link(&report.directory.base_url));
    doc.field("IDP", Line::text(&report.idp.issuer));
    certificate_lines(&mut doc, &report.idp.certificates);
    doc.field("identity", Line::text(&report.identity.subject));
    if let Some(id) = &report.identity.telematik_id {
        doc.field("Telematik-ID", Line::code(id));
    }
    if let Some(sub) = &report.token.sub
        && Some(sub) != report.identity.telematik_id.as_ref()
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
