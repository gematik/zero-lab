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

//! `ti connector …`: the Konnektor's cards, certificates and PINs, with the Go `ti`'s
//! commands and `.kon` files. Listings are tables, single records fields.

use std::cell::Cell;
use std::path::Path;

use serde::Serialize;
use ti_client::connector::store;
use ti_client::connector::{Prompt, Wait, cards as engine};
use ti_connector_client::model::{
    Card, CardDescription, CertificateCheck, Info, PinOutcome, PinStatus, Services, Severity,
    Status,
};
use ti_connector_client::types::{Crypt, VerificationResult};
use ti_pki::{Certificate, Timestamp};

use super::inspect;
use crate::cli::{
    ConnectorArgs, ConnectorChange, ConnectorCli, ConnectorCommand, ConnectorConfig,
    ConnectorDescribe, ConnectorGet, ConnectorVerify, GlobalArgs, PinArgs,
};
use crate::connector::{self, Session};
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{date, when};
use crate::output::{Document, Line, Output, SCHEMA, Tone, Waiting};

/// Runs `ti connector …`.
pub fn run(cli: &ConnectorCli, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    // A command that talks to the Konnektor opens its session through `open`; its errors
    // then name that configuration.
    let opened = Cell::new(false);
    let open = || {
        opened.set(true);
        connector::open(&cli.args, global, out)
    };
    let result = command(cli, global, out, &open);
    if opened.get() {
        let name = connector::selected_name(&cli.args);
        result.map_err(|error| error.for_connector(&name))
    } else {
        result
    }
}

fn command(
    cli: &ConnectorCli,
    global: &GlobalArgs,
    out: &Output,
    open: &dyn Fn() -> Result<Session, CliError>,
) -> Result<Exit, CliError> {
    match &cli.command {
        ConnectorCommand::Configs
        | ConnectorCommand::Use { name: None }
        | ConnectorCommand::Config(ConnectorConfig::List) => configs(&cli.args, out),
        ConnectorCommand::Use { name: Some(name) } => use_config(name, out),
        ConnectorCommand::Config(ConnectorConfig::Show { name }) => {
            super::connector_config::show(name.as_deref(), &cli.args, out)
        }
        ConnectorCommand::Config(ConnectorConfig::Test { name }) => {
            super::connector_config::test(name.as_deref(), &cli.args, global, out)
        }
        ConnectorCommand::Config(ConnectorConfig::New(args)) => {
            super::connector_setup::new(args, &cli.args, global, out)
        }
        ConnectorCommand::Config(ConnectorConfig::Edit(args)) => {
            super::connector_setup::edit(args, &cli.args, out)
        }
        ConnectorCommand::Config(ConnectorConfig::Set { assignments }) => {
            super::connector_setup::set(assignments, &cli.args, out)
        }
        ConnectorCommand::Config(ConnectorConfig::Pin(args)) => {
            super::connector_setup::pin(args, &cli.args, global, out)
        }
        ConnectorCommand::Get(ConnectorGet::Info) => info(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Services) => services(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Cards) => cards(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Certificates { card }) => {
            certificates(&open()?, card, out)
        }
        ConnectorCommand::Get(ConnectorGet::Status) => status(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Identities) => identities(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Expiration { card, crypt }) => {
            expiration(&open()?, card.as_deref(), (*crypt).into(), out)
        }
        ConnectorCommand::Describe(ConnectorDescribe::Card { card }) => {
            describe_card(&open()?, card, out)
        }
        ConnectorCommand::Describe(ConnectorDescribe::Certificate(args)) => {
            let session = open()?;
            let (what, certificate) =
                engine::card_certificate(&session, &args.card, args.cert_ref, args.crypt.into())?;
            inspect::show(what, vec![certificate], global, out)
        }
        ConnectorCommand::Verify(ConnectorVerify::Pin(args)) => {
            pin(&open()?, &cli.args, args, false, out)
        }
        ConnectorCommand::Change(ConnectorChange::Pin(args)) => {
            pin(&open()?, &cli.args, args, true, out)
        }
        ConnectorCommand::Sign(args) => super::documents::sign(&open()?, &cli.args, args, out),
        ConnectorCommand::Encrypt(args) => super::documents::encrypt(&open()?, args, out),
        ConnectorCommand::Decrypt(args) => {
            super::documents::decrypt(&open()?, &cli.args, args, out)
        }
        ConnectorCommand::Export(crate::cli::ConnectorExport::Certificate(args)) => {
            super::documents::export(&open()?, args, out)
        }
        ConnectorCommand::Comfort(command) => {
            super::documents::comfort(&open()?, &cli.args, command, out)
        }
        ConnectorCommand::Verify(ConnectorVerify::Signature {
            file,
            signature,
            mime_type,
        }) => super::documents::verify_signature(
            &open()?,
            file,
            signature.as_deref(),
            mime_type.as_deref(),
            out,
        ),
        ConnectorCommand::Verify(ConnectorVerify::Certificate {
            card,
            cert_ref,
            file,
            p12_password,
            crypt,
            at,
        }) => {
            let session = open()?;
            let (source, certificate) = match (card, cert_ref, file) {
                (_, _, Some(file)) => from_file(file, p12_password)?,
                (Some(card), Some(cert_ref), None) => {
                    engine::card_certificate(&session, card, *cert_ref, (*crypt).into())?
                }
                _ => unreachable!("clap requires CARD REF or --file"),
            };
            verify_certificate(&session, &source, &certificate, *at, out)
        }
    }
}

/// The report as JSON with the `schema` version, or `view` rendered as text.
pub(super) fn emit<T: Serialize>(
    out: &Output,
    exit: Exit,
    report: &T,
    view: impl FnOnce(&mut Document),
) -> Result<Exit, CliError> {
    #[derive(Serialize)]
    struct Versioned<'a, T> {
        schema: u32,
        #[serde(flatten)]
        report: &'a T,
    }
    if out.is_json() {
        out.json(&Versioned {
            schema: SCHEMA,
            report,
        })?;
    } else {
        let mut doc = Document::default();
        view(&mut doc);
        out.render(&doc)?;
    }
    Ok(exit)
}

/// An optional value as a cell; `-` for none.
fn cell(value: Option<&str>) -> Line {
    Line::text(value.unwrap_or("-"))
}

/// The line shown while a call waits at the card terminal, for `timeout`; dropping it
/// ends it.
pub(super) fn waiting(args: &ConnectorArgs) -> impl FnOnce(&Wait<'_>) -> Waiting + '_ {
    |wait| {
        let message = match wait.prompt {
            Prompt::EnterPin(pin) => format!("Enter {pin} at the card terminal"),
            Prompt::ChangePin(pin) => format!("Change {pin} at the card terminal"),
            Prompt::SignWithPin => "Enter PIN.QES at the card terminal".to_owned(),
            Prompt::Sign => "Signing with the card".to_owned(),
            Prompt::Decrypt => "Decrypting with the card".to_owned(),
            Prompt::ActivateComfort => {
                "Enter PIN.QES at the card terminal to activate comfort signature".to_owned()
            }
        };
        let detail = match wait.job_number {
            Some(job) => format!("{} · job {job}", wait.card.label()),
            None => wait.card.label(),
        };
        Waiting::start(&message, &detail, args.card_timeout)
    }
}

pub(super) fn from_file(
    file: &Path,
    p12_password: &str,
) -> Result<(String, Certificate), CliError> {
    let input = input::read(file)?;
    let first = input::certificates(&input, p12_password)?.remove(0);
    Ok((input.name, first.certificate))
}

// ---- configurations ----------------------------------------------------------------

fn configs(args: &ConnectorArgs, out: &Output) -> Result<Exit, CliError> {
    let report = store::list(args.connector_config.as_deref());
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.configurations.iter().map(|c| {
            // `*` first marks the configuration commands use without -c.
            let name = if c.name == report.selected {
                Line::strong(format!("* {}", c.name))
            } else {
                Line::text(format!("  {}", c.name))
            };
            let (url, context) = match &c.error {
                Some(error) => (Line::status(Tone::Bad, error), Line::text("")),
                None => (
                    Line::code(c.url.as_deref().unwrap_or("")),
                    cell(c.context.as_deref()),
                ),
            };
            vec![name, url, context]
        });
        doc.table(&["  NAME", "URL", "CONTEXT"], rows.collect());
        if report.configurations.is_empty() {
            doc.paragraph(Line::dim(
                "no .kon files here or in ~/.config/telematik/connectors",
            ));
        }
    })
}

fn use_config(name: &str, out: &Output) -> Result<Exit, CliError> {
    let report = store::select(name)?;
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "selected",
            Line::strong(&report.name).and_dim(format!(" · {}", report.path)),
        );
    })
}

// ---- get -----------------------------------------------------------------------------

fn info(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let r: Info = engine::info(session);
    emit(out, Exit::Ok, &r, |doc| {
        let p = &r.product;
        let context = format!("{}/{}/{}", r.mandant_id, r.workplace_id, r.client_system_id);
        doc.section("Connector");
        doc.field("name", Line::strong(&r.name));
        doc.field("url", Line::code(&r.url));
        doc.field(
            "context",
            Line::text(context).and_dim(" · mandant/workplace/client system"),
        );
        if let Some(user) = &r.user_id {
            doc.field("user", user.as_str());
        }
        doc.field("credentials", r.credentials);
        if let Some(env) = &r.environment {
            doc.field("environment", env.as_str());
        }
        doc.section("Product");
        let name = p.product_name.as_deref().unwrap_or(&p.product_code);
        let vendor = p.vendor_name.as_deref().unwrap_or(&p.vendor_id);
        doc.field(
            "product",
            Line::strong(format!("{vendor} {name}")).and_dim(format!(" · {}", p.product_code)),
        );
        doc.field(
            "type",
            format!("{} {}", p.product_type, p.product_type_version),
        );
        doc.field(
            "firmware",
            Line::text(&p.fw_version).and_dim(format!(" · hardware {}", p.hw_version)),
        );
    })
}

fn services(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let report: Services = engine::services(session);
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.services.iter().flat_map(|s| {
            s.versions.iter().map(|v| {
                let used = if v.used {
                    Line::status(Tone::Good, "used")
                } else {
                    Line::text("")
                };
                vec![
                    Line::strong(&s.name),
                    Line::code(&v.version),
                    used,
                    cell(v.endpoint.as_deref()),
                ]
            })
        });
        doc.table(&["SERVICE", "VERSION", "", "ENDPOINT"], rows.collect());
    })
}

/// Identifiers longer than this are shortened in tables; JSON and `-v` keep them whole.
const CELL_WIDTH: usize = 20;

/// `0a1b2c3d…7e8f9a0b` for a value longer than [`CELL_WIDTH`] unless `full`: UUID-shaped
/// handles and terminal IDs would widen the table past a terminal, and their start and
/// end still tell the rows apart.
fn shorten(value: &str, full: bool) -> String {
    let n = value.chars().count();
    if full || n <= CELL_WIDTH {
        return value.to_owned();
    }
    let head: String = value.chars().take(8).collect();
    let tail: String = value.chars().skip(n - 8).collect();
    format!("{head}…{tail}")
}

/// The table of `cards`; `full` keeps long identifiers whole.
fn card_table(doc: &mut Document, cards: &[&Card], full: bool) {
    let rows = cards.iter().map(|c| {
        vec![
            Line::code(shorten(&c.handle, full)),
            Line::strong(c.card_type),
            cell(c.iccsn.as_deref()),
            Line::text(shorten(&c.terminal, full)).and_dim(format!(" · slot {}", c.slot)),
            cell(c.holder.as_deref()),
        ]
    });
    let headings = ["HANDLE", "TYPE", "ICCSN", "TERMINAL", "HOLDER"];
    doc.table(&headings, rows.collect());
}

#[derive(Serialize)]
struct CardsReport {
    cards: Vec<Card>,
}

fn cards(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let report = CardsReport {
        cards: engine::cards(session)?,
    };
    emit(out, Exit::Ok, &report, |doc| {
        card_table(
            doc,
            &report.cards.iter().collect::<Vec<_>>(),
            out.verbosity() > 0,
        );
        if report.cards.is_empty() {
            doc.paragraph(Line::dim("no card in the card terminals"));
        }
    })
}

fn certificates(session: &Session, card: &str, out: &Output) -> Result<Exit, CliError> {
    let report = engine::certificates(session, card)?;
    emit(out, Exit::Ok, &report, |doc| {
        doc.section("Card");
        card_table(doc, &[&report.card], out.verbosity() > 0);
        // A card's certificates usually name one holder: said once above the table, a
        // column only where they differ.
        let certs = &report.certificates;
        let shared = |value: fn(&ti_connector_client::model::Certificate) -> Option<&str>| {
            let first = value(certs.first()?);
            certs.iter().all(|c| value(c) == first).then_some(first)
        };
        let subject = shared(|c| Some(c.subject.as_str()));
        let telematik_id = shared(|c| c.telematik_id.as_deref());
        doc.section("Certificates");
        if let Some(Some(subject)) = subject {
            doc.field("subject", subject);
        }
        if let Some(Some(id)) = telematik_id {
            doc.field("Telematik-ID", Line::code(id));
        }
        let mut headings = vec!["REF", "KEY"];
        if subject.is_none() {
            headings.push("SUBJECT");
        }
        if telematik_id.is_none() {
            headings.push("TELEMATIK-ID");
        }
        headings.extend(["VALIDITY", "ALGORITHM"]);
        let rows = certs.iter().map(|c| {
            let mut row = vec![Line::strong(c.cert_ref), Line::text(c.crypt)];
            if subject.is_none() {
                row.push(Line::text(&c.subject));
            }
            if telematik_id.is_none() {
                row.push(Line::code(c.telematik_id.as_deref().unwrap_or("-")));
            }
            row.push(super::validity_cell(c.not_after_at, c.validity));
            row.push(Line::dim(&c.key));
            row
        });
        doc.table(&headings, rows.collect());
        for c in &report.certificates {
            doc.pem(&c.pem);
        }
    })
}

fn status(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let report: Status = engine::status(session)?;
    emit(out, Exit::Ok, &report, |doc| {
        doc.section("Konnektor");
        for (label, vpn) in [("VPN TI", &report.vpn_ti), ("VPN SIS", &report.vpn_sis)] {
            if let Some(vpn) = vpn {
                let online = vpn.status.eq_ignore_ascii_case("online");
                let tone = if online { Tone::Good } else { Tone::Bad };
                let since = format!(" · since {}", vpn.since);
                doc.field(label, Line::status(tone, &vpn.status).and_dim(since));
            }
        }
        let active: Vec<Vec<Line>> = report
            .errors
            .iter()
            .filter(|e| e.active)
            .map(|e| {
                vec![
                    condition_line(&e.condition, &e.severity),
                    Line::text(&e.severity),
                    Line::text(&e.kind),
                    Line::dim(&e.since),
                ]
            })
            .collect();
        if active.is_empty() {
            doc.field("errors", Line::status(Tone::Good, "none"));
        } else {
            doc.section("Errors");
            doc.table(&["CONDITION", "SEVERITY", "TYPE", "SINCE"], active);
        }
    })
}

/// An active condition, colored by its severity (gemSpec_Kon TAB_KON_503): a severity
/// that is not known stays red.
fn condition_line(condition: &str, severity: &str) -> Line {
    match Severity::of(severity) {
        Severity::Info => Line::text(condition),
        Severity::Warning => Line::status(Tone::Warn, condition),
        Severity::Error => Line::status(Tone::Bad, condition),
    }
}

#[derive(Serialize)]
struct IdentitiesReport {
    identities: Vec<ti_connector_client::model::Identity>,
}

fn identities(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let report = IdentitiesReport {
        identities: engine::identities(session)?,
    };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.identities.iter().map(|i| {
            vec![
                Line::code(i.telematik_id.as_deref().unwrap_or("-")),
                Line::strong(i.card_type),
                cell(i.holder.as_deref()),
                cell(i.iccsn.as_deref()),
                Line::code(shorten(&i.handle, out.verbosity() > 0)),
            ]
        });
        doc.table(
            &["TELEMATIK-ID", "TYPE", "HOLDER", "ICCSN", "HANDLE"],
            rows.collect(),
        );
    })
}

#[derive(Serialize)]
struct ExpirationReport {
    certificates: Vec<ti_connector_client::model::Expiration>,
}

fn expiration(
    session: &Session,
    card: Option<&str>,
    crypt: Crypt,
    out: &Output,
) -> Result<Exit, CliError> {
    let report = ExpirationReport {
        certificates: engine::expiration(session, card, crypt)?,
    };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.certificates.iter().map(|e| {
            vec![
                Line::strong(&e.validity),
                Line::text(&e.subject),
                Line::code(&e.iccsn),
                Line::text(&e.serial),
                Line::code(shorten(&e.handle, out.verbosity() > 0)),
            ]
        });
        doc.table(
            &["VALID UNTIL", "SUBJECT", "ICCSN", "SERIAL", "HANDLE"],
            rows.collect(),
        );
    })
}

// ---- describe ------------------------------------------------------------------------

/// `verified`, or `PIN entry needed · 3 tries left` and the like, by what it means for
/// the next signature.
fn pin_line(p: &PinStatus) -> Line {
    let tries = |line: Line| match p.left_tries {
        Some(n) => line.and_dim(format!(
            " · {n} {} left",
            if n == 1 { "try" } else { "tries" }
        )),
        None => line,
    };
    match (p.status, &p.error) {
        (_, Some(error)) => Line::status(Tone::Warn, "unknown").and_dim(format!(" ({error})")),
        (Some("VERIFIED"), _) => Line::status(Tone::Good, "verified"),
        (Some("VERIFIABLE"), _) => tries(Line::status(Tone::Warn, "PIN entry needed")),
        (Some("TRANSPORT_PIN"), _) => {
            tries(Line::status(Tone::Warn, "transport PIN: set a PIN first"))
        }
        (Some("EMPTY_PIN"), _) => Line::status(Tone::Warn, "no PIN set: set one first"),
        (Some("BLOCKED"), _) => Line::status(Tone::Bad, "blocked: unblock with the PUK"),
        (Some("DISABLED"), _) => Line::dim("disabled"),
        _ => Line::dim("no status"),
    }
}

/// An `xsd:dateTime` of the Konnektor in local time, as every time `ti` shows; as sent
/// if it does not parse.
fn local_time(value: &str) -> String {
    value
        .parse::<jiff::Timestamp>()
        .ok()
        .and_then(|t| u64::try_from(t.as_second()).ok())
        .map_or_else(|| value.to_owned(), |secs| when(Timestamp(secs)))
}

/// An `xsd:date` without its zone, e.g. `2029-10-08Z` as `2029-10-08`: a day is what an
/// expiry date says.
fn xsd_date(value: &str) -> &str {
    match value.get(..10) {
        Some(day) if day.as_bytes().get(4) == Some(&b'-') => day,
        _ => value,
    }
}

fn describe_card(session: &Session, card: &str, out: &Output) -> Result<Exit, CliError> {
    let report: CardDescription = engine::describe(session, card)?;
    emit(out, Exit::Ok, &report, |doc| {
        let c = &report.card;
        doc.section("Card");
        doc.field("type", Line::strong(c.card_type));
        doc.field("ICCSN", Line::code(c.iccsn.as_deref().unwrap_or("-")));
        if let Some(holder) = &c.holder {
            doc.field("holder", holder.as_str());
        }
        if let Some(id) = &report.telematik_id {
            doc.field("Telematik-ID", Line::code(id));
        }
        if let Some(kvnr) = &c.kvnr {
            doc.field("KVNR", Line::code(kvnr));
        }
        doc.field(
            "terminal",
            Line::text(&c.terminal).and_dim(format!(" · slot {}", c.slot)),
        );
        doc.field("inserted", local_time(&c.inserted));
        if let Some(expiry) = &c.certificate_expiration {
            doc.field("valid until", xsd_date(expiry));
        }
        if let (Some(cos), Some(os)) = (&c.cos_version, &c.object_system_version) {
            let os = format!(" · object system {os}");
            doc.field("versions", Line::text(format!("COS {cos}")).and_dim(os));
        }
        doc.field("handle", Line::code(&c.handle));
        for p in &report.pins {
            doc.field(p.pin, pin_line(p));
        }
    })
}

// ---- verify and change ---------------------------------------------------------------

fn pin(
    session: &Session,
    args: &ConnectorArgs,
    pin: &PinArgs,
    change: bool,
    out: &Output,
) -> Result<Exit, CliError> {
    let report: PinOutcome = engine::pin(session, &pin.card, pin.pin, change, waiting(args))?;
    let accepted = report.accepted();
    let exit = if accepted { Exit::Ok } else { Exit::Invalid };
    emit(out, exit, &report, |doc| {
        let tone = if accepted { Tone::Good } else { Tone::Bad };
        let mut result = Line::status(tone, report.result);
        if let Some(tries) = report.left_tries {
            result = result.and_dim(format!(" · {tries} tries left"));
        }
        doc.field(
            if change {
                "PIN change"
            } else {
                "PIN verification"
            },
            result,
        );
        doc.field("PIN", report.pin);
        doc.field("card", report.card.label());
    })
}

#[derive(Serialize)]
struct VerifyReport<'a> {
    source: &'a str,
    #[serde(flatten)]
    check: &'a CertificateCheck,
}

fn verify_certificate(
    session: &Session,
    source: &str,
    certificate: &Certificate,
    at: Option<Timestamp>,
    out: &Output,
) -> Result<Exit, CliError> {
    let check = engine::verify_certificate(session, certificate, at)?;
    let report = VerifyReport {
        source,
        check: &check,
    };
    let exit = if check.valid() {
        Exit::Ok
    } else {
        Exit::Invalid
    };
    emit(out, exit, &report, |doc| {
        let tone = if check.valid() {
            Tone::Good
        } else if check.result == VerificationResult::Inconclusive.as_str() {
            Tone::Warn
        } else {
            Tone::Bad
        };
        let what = " · the Konnektor's check: path and OCSP";
        doc.field("result", Line::status(tone, check.result).and_dim(what));
        let source = format!(" · {source}");
        doc.field("certificate", Line::strong(&check.subject).and_dim(source));
        if let Some(at) = at {
            doc.field("at", date(at));
        }
        doc.items("roles", check.roles.iter().map(Line::code));
        doc.items(
            "errors",
            check.errors.iter().map(|e| Line::status(Tone::Bad, e)),
        );
    })
}

#[cfg(test)]
mod tests {
    use super::shorten;

    #[test]
    fn long_identifiers_are_shortened_unless_full() {
        let handle = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
        assert_eq!(shorten(handle, false), "0a1b2c3d…2a3b4c5d");
        assert_eq!(shorten(handle, true), handle);
        assert_eq!(shorten("CT1", false), "CT1");
        assert_eq!(
            shorten("80276001011699910102", false),
            "80276001011699910102"
        );
    }

    /// TAB_KON_503: an Info condition is no fault, and a severity not known stays red.
    #[test]
    fn tab_kon_503_a_condition_is_colored_by_its_severity() {
        use super::{Line, Tone, condition_line};
        let c = "EC_X";
        assert_eq!(condition_line(c, "Info"), Line::text(c));
        assert_eq!(condition_line(c, "INFO"), Line::text(c));
        assert_eq!(condition_line(c, "Warning"), Line::status(Tone::Warn, c));
        for severity in ["Error", "Fatal", "Something new", ""] {
            assert_eq!(condition_line(c, severity), Line::status(Tone::Bad, c));
        }
    }
}
