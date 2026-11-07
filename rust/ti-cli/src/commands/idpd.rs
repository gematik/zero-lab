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

//! `ti idpd authenticate`: the IDP-Dienst's Authenticator-Modul flow with an identity,
//! from an authorization URL to the authorization code. What an ePA client does for
//! `send_authorization_request_sc` → `send_authcode_sc`.

use serde::Serialize;
use ti_client::idpd::{self, Authentication, Card};
use ti_idpd_client::Idp;
use ti_idpd_client::model::CertificateInfo;

use super::idp_trust::idp_trust;
use crate::cli::{GlobalArgs, IdpdAuthenticateArgs};
use crate::error::{CliError, Exit};
use crate::http;
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    #[serde(flatten)]
    authentication: &'a Authentication,
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
    let identity = crate::identity::load(&args.identity, global, out)?;
    let card = Card::new(&identity)?;
    let transport = http::Logged::new(&global.net, out)?;
    out.verbose(1, format_args!("IDP-Dienst {}", idp.base_url()));
    let trust = idp_trust(args.idp_unverified, args.env, global, out);
    let done = idpd::authenticate(&transport, &idp, &card, &args.auth_url, &trust)?;
    if out.is_json() {
        out.json(&Report {
            schema: SCHEMA,
            authentication: &done,
        })?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.field("authenticated", Line::status(Tone::Good, "code received"));
    doc.field("IDP", Line::text(&done.idp.issuer));
    certificate_lines(&mut doc, &done.idp.certificates);
    doc.field(
        "client",
        Line::text(done.challenge.client_id.as_deref().unwrap_or("-")),
    );
    doc.field("identity", Line::text(&done.identity.subject));
    if let Some(id) = &done.identity.telematik_id {
        doc.field("Telematik-ID", Line::code(id));
    }
    doc.field("code", Line::code(&done.code));
    if let Some(state) = &done.state {
        doc.field("state", Line::code(state));
    }
    doc.field("redirect", Line::link(&done.redirect_url));
    for warning in &done.warnings {
        doc.field("warning", Line::status(Tone::Warn, *warning));
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// One line per IDP certificate: verified against the TSL, or not checked.
pub(super) fn certificate_lines(doc: &mut Document, certificates: &[CertificateInfo]) {
    for c in certificates {
        let line = if c.verified {
            Line::status(Tone::Good, "valid (TSL, OCSP)")
        } else {
            Line::status(Tone::Warn, "not checked")
        };
        doc.field(c.key, line.and_dim(" · ").and_line(Line::text(&c.subject)));
    }
}
