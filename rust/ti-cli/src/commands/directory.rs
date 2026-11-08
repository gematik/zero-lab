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

//! `ti directory login owner|search|holder|service|ti-provider`: a FHIR-Directory access
//! token from one of its Auth-Service endpoints, by card through the IDP-Dienst, with a
//! TI-Messenger RegService-OpenID-Token, or with client credentials at the directory's
//! Keycloak. `search` is the owner token of a card, named for the Search API it opens.

use serde::Serialize;
use ti_client::directory::{self as engine, Login};
use ti_client::idpd::Card;
use ti_directory_client::{Directory, Endpoint};
use ti_pki::Timestamp;

use super::idp_trust::idp_trust;
use super::idpd::certificate_lines;
use crate::cli::{
    DirectoryClientArgs, DirectoryLoginCommand, DirectoryOwnerArgs, DirectorySearchArgs,
    DirectoryTargetArgs, GlobalArgs, IdentityArgs,
};
use crate::error::{CliError, Exit};
use crate::http;
use crate::output::document::when;

use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document, one for every path.
#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    #[serde(flatten)]
    login: &'a Login,
}

/// Runs `ti directory login …`.
pub fn login(
    command: &DirectoryLoginCommand,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    match command {
        DirectoryLoginCommand::Owner(args) => login_owner(args, global, out),
        DirectoryLoginCommand::Search(args) => login_search(args, global, out),
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
            (Some(idp), _) => idp,
            (None, Needs::Idp) => {
                return Err(CliError::Arguments(
                    "a card login at --url needs the directory's IDP-Dienst: --idp-url".into(),
                ));
            }
            // Never contacted: only a card login goes to the IDP.
            (None, _) => url,
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

fn login_client(
    args: &DirectoryClientArgs,
    endpoint: Endpoint,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let directory = directory(&args.target, Needs::Keycloak)?;
    let secret = crate::input::first_line(&args.client_secret_path)?;
    let transport = http::client(&global.net, out.verbosity()).idp()?;
    out.verbose(
        1,
        format_args!(
            "FHIR-Directory {} via Keycloak {}, realm {}",
            directory.base_url(),
            directory.auth_url().unwrap_or("-"),
            endpoint.realm().unwrap_or("-")
        ),
    );
    let login =
        engine::client_credentials(&transport, &directory, endpoint, &args.client_id, &secret)?;
    emit(&login, &args.target, out)
}

fn login_owner(
    args: &DirectoryOwnerArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    if let Some(path) = &args.regservice_token_path {
        let directory = directory(&args.target, Needs::Nothing)?;
        let bearer = crate::input::first_line(path)?;
        let transport = http::client(&global.net, out.verbosity()).idp()?;
        let login = engine::regservice(&transport, &directory, &bearer)?;
        return emit(&login, &args.target, out);
    }
    let Some(identity_args) = &args.identity else {
        return Err(CliError::Arguments(
            "an owner login needs a card identity (--p12, --cert/--key, --card) or --regservice-token-path".into(),
        ));
    };
    let login = login_card(
        identity_args,
        &args.target,
        args.idp_unverified,
        false,
        global,
        out,
    )?;
    emit(&login, &args.target, out)
}

fn login_search(
    args: &DirectorySearchArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let login = login_card(
        &args.identity,
        &args.target,
        args.idp_unverified,
        true,
        global,
        out,
    )?;
    emit(&login, &args.target, out)
}

/// The owner token of a card identity, through the directory's IDP-Dienst; for its
/// Search API with `search`.
fn login_card(
    identity_args: &IdentityArgs,
    target: &DirectoryTargetArgs,
    idp_unverified: bool,
    search: bool,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Login, CliError> {
    let directory = directory(target, Needs::Idp)?;
    let identity = crate::identity::load(identity_args, global, out)?;
    let card = Card::new(&identity)?;
    let transport = http::client(&global.net, out.verbosity()).idp()?;
    out.verbose(
        1,
        format_args!(
            "FHIR-Directory {} via IDP-Dienst {}",
            directory.base_url(),
            directory.idp_url()
        ),
    );
    let trust = idp_trust(idp_unverified, target.env, global, out);
    if search {
        engine::search(&transport, &directory, &card, &trust)
    } else {
        engine::card(&transport, &directory, &card, &trust)
    }
}

fn emit(login: &Login, target: &DirectoryTargetArgs, out: &Output) -> Result<Exit, CliError> {
    if target.token {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", login.token.access_token)?;
        return Ok(Exit::Ok);
    }
    if out.is_json() {
        out.json(&Report {
            schema: SCHEMA,
            login,
        })?;
    } else {
        out.render(&document(login))?;
    }
    Ok(Exit::Ok)
}

/// The text view.
fn document(login: &Login) -> Document {
    let token = &login.token;
    let mut doc = Document::default();
    doc.field(
        "authenticated",
        Line::status(Tone::Good, format!("{} token received", token.endpoint))
            .and_dim(format!(" · {}", token.method.replace('_', " "))),
    );
    doc.field("endpoint", Line::link(&token.directory.endpoint_url));
    if let Some(search) = &token.directory.search_url {
        doc.field("for", Line::link(search));
    }
    if let Some(idp) = &login.idp {
        doc.field("IDP", Line::text(&idp.issuer));
        certificate_lines(&mut doc, &idp.certificates);
    }
    if let Some(identity) = &login.identity {
        doc.field("identity", Line::text(&identity.subject));
        if let Some(id) = &identity.telematik_id {
            doc.field("Telematik-ID", Line::code(id));
        }
    }
    if let Some(client) = &login.client_id {
        doc.field("client", Line::code(client));
    }
    let shown_id = login
        .identity
        .as_ref()
        .and_then(|i| i.telematik_id.as_ref())
        .or(login.client_id.as_ref());
    if let Some(sub) = &token.token.sub
        && Some(sub) != shown_id
    {
        doc.field("subject", Line::code(sub));
    }
    if let Some(scope) = &token.token.scope {
        doc.field("scope", Line::text(scope));
    }
    doc.field(
        "expires",
        Line::text(format!(
            "{} ({} h)",
            when(Timestamp(token.expires_at)),
            token.expires_in / 3600
        )),
    );
    doc.field("token", Line::code(&token.access_token));
    for warning in &login.warnings {
        doc.field("warning", Line::status(Tone::Warn, *warning));
    }
    doc
}
