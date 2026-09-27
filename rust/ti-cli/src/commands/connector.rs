//! `ti connector …`: the Konnektor's cards, certificates and PINs, with the Go `ti`'s
//! commands and `.kon` files. Listings are tables, single records fields.

use std::path::{Path, PathBuf};

use serde::Serialize;
use ti_connector_client::types::{Card, CardType, CertRef, Crypt, PinResult, VerificationResult};
use ti_connector_client::{BINDINGS, Credentials, Error, PinType, Product};
use ti_pki::load::SystemClock;
use ti_pki::{Certificate, Clock, Timestamp};

use super::inspect;
use crate::block::block_on;
use crate::cli::{
    ConnectorArgs, ConnectorChange, ConnectorCli, ConnectorCommand, ConnectorDescribe,
    ConnectorGet, ConnectorVerify, CryptArg, GlobalArgs, PinArgs,
};
use crate::connector::{self, Session};
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::date;
use crate::output::{Document, Line, Output, SCHEMA, Tone, Waiting, pem};

/// Runs `ti connector …`.
pub fn run(cli: &ConnectorCli, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let open = || connector::open(&cli.args, global, out);
    match &cli.command {
        ConnectorCommand::Configs => configs(&cli.args, out),
        ConnectorCommand::Use { name } => use_config(name, out),
        ConnectorCommand::Get(ConnectorGet::Info) => info(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Services) => services(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Cards) => cards(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Certificates { card }) => {
            certificates(&open()?, card, out)
        }
        ConnectorCommand::Get(ConnectorGet::Status) => status(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Identities) => identities(&open()?, out),
        ConnectorCommand::Get(ConnectorGet::Expiration { card, crypt }) => {
            expiration(&open()?, card.as_deref(), *crypt, out)
        }
        ConnectorCommand::Describe(ConnectorDescribe::Card { card }) => {
            describe_card(&open()?, card, out)
        }
        ConnectorCommand::Describe(ConnectorDescribe::Certificate(args)) => {
            let session = open()?;
            let (what, certificate) =
                card_certificate(&session, &args.card, args.cert_ref, args.crypt)?;
            inspect::show(what, vec![certificate], out)
        }
        ConnectorCommand::Verify(ConnectorVerify::Pin(args)) => {
            pin(&open()?, &cli.args, args, false, out)
        }
        ConnectorCommand::Change(ConnectorChange::Pin(args)) => {
            pin(&open()?, &cli.args, args, true, out)
        }
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
                    card_certificate(&session, card, *cert_ref, *crypt)?
                }
                _ => unreachable!("clap requires CARD REF or --file"),
            };
            verify_certificate(&session, &source, &certificate, *at, out)
        }
    }
}

/// The report as JSON with the `schema` version, or `view` rendered as text.
fn emit<T: Serialize>(
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

/// Runs a Konnektor call.
fn call<T>(future: impl Future<Output = Result<T, Error>>) -> Result<T, CliError> {
    block_on(future).map_err(CliError::Connector)
}

/// Runs a call about `card`; a refusal for a card type the Konnektor restricts on its
/// SOAP API (SMC-KT, KVK, eGK) says so.
fn card_call<T>(
    card: &Card,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, CliError> {
    block_on(future).map_err(|error| match (card.card_type, error) {
        (CardType::SmcKt | CardType::Kvk | CardType::Egk, error @ Error::Fault(_)) => {
            CliError::CardRestricted {
                card_type: card.card_type.to_string(),
                source: error,
            }
        }
        (_, error) => CliError::Connector(error),
    })
}

fn find(session: &Session, card: &str) -> Result<Card, CliError> {
    call(session.connector.cards().find(card))
}

/// `SMC-B 80276001011699910102`, or the handle for a card without ICCSN.
fn card_label(card: &Card) -> String {
    let id = card.iccsn.as_deref().unwrap_or(&card.card_handle);
    format!("{} {id}", card.card_type)
}

/// Certificate `cert_ref` of `crypt` from `card`, with a description of where it came
/// from.
fn card_certificate(
    session: &Session,
    card: &str,
    cert_ref: CertRef,
    crypt: CryptArg,
) -> Result<(String, Certificate), CliError> {
    let card = find(session, card)?;
    let crypt = Crypt::from(crypt);
    let certificates = session.connector.certificates();
    let read = card_call(
        &card,
        certificates.read(&card.card_handle, crypt, &[cert_ref]),
    )?;
    let what = format!("{cert_ref} {crypt} of {}", card_label(&card));
    match read.into_iter().next() {
        Some(c) => Ok((what, c.certificate)),
        None => Err(CliError::NoCertificate { source_name: what }),
    }
}

fn from_file(file: &Path, p12_password: &str) -> Result<(String, Certificate), CliError> {
    let input = input::read(file)?;
    let first = input::certificates(&input, p12_password)?.remove(0);
    Ok((input.name, first.certificate))
}

// ---- configurations ----------------------------------------------------------------

#[derive(Serialize)]
struct ConfigsReport {
    /// The configuration commands use without -c.
    selected: String,
    configurations: Vec<ConfigInfo>,
}

#[derive(Serialize)]
struct ConfigInfo {
    name: String,
    path: String,
    url: Option<String>,
    /// `mandant/workplace/client system`.
    context: Option<String>,
    /// Why the file cannot be used.
    error: Option<String>,
}

fn configs(args: &ConnectorArgs, out: &Output) -> Result<Exit, CliError> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for dir in [Some(PathBuf::from(".")), connector::connectors_dir()]
        .into_iter()
        .flatten()
    {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "kon"))
            .collect();
        found.sort();
        paths.extend(found);
    }
    let configurations = paths
        .into_iter()
        .map(|path| {
            let kon = connector::read(&path);
            ConfigInfo {
                name: path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                path: path.display().to_string(),
                url: kon.as_ref().ok().map(|k| k.url.clone()),
                context: kon
                    .as_ref()
                    .ok()
                    .map(|k| format!("{}/{}/{}", k.mandant_id, k.workplace_id, k.client_system_id)),
                error: kon.err().map(|e| e.to_string()),
            }
        })
        .collect();
    let report = ConfigsReport {
        selected: connector::selected(args.connector_config.as_deref()).0,
        configurations,
    };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.configurations.iter().map(|c| {
            let name = if c.name == report.selected {
                Line::strong(&c.name)
                    .and_text(" ")
                    .and_status(Tone::Good, "*")
            } else {
                Line::text(&c.name)
            };
            let (url, context) = match &c.error {
                Some(error) => (Line::status(Tone::Bad, error), Line::text("")),
                None => (
                    Line::code(c.url.as_deref().unwrap_or("")),
                    cell(c.context.as_deref()),
                ),
            };
            vec![name, url, context, Line::dim(&c.path)]
        });
        doc.table(&["NAME", "URL", "CONTEXT", "PATH"], rows.collect());
        if report.configurations.is_empty() {
            doc.paragraph(Line::dim(
                "no .kon files here or in ~/.config/telematik/connectors",
            ));
        }
    })
}

#[derive(Serialize)]
struct UseReport {
    name: String,
    path: String,
}

fn use_config(name: &str, out: &Output) -> Result<Exit, CliError> {
    let path = connector::resolve(name)?;
    connector::read(&path)?;
    let file = connector::active_file().ok_or_else(|| {
        CliError::ConnectorConfig("no home directory for the active selection".into())
    })?;
    let write = || -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&file, format!("{name}\n"))
    };
    write().map_err(|e| {
        CliError::Output(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", file.display()),
        ))
    })?;
    let report = UseReport {
        name: name.to_owned(),
        path: path.display().to_string(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "selected",
            Line::strong(&report.name).and_dim(format!(" · {}", report.path)),
        );
    })
}

// ---- get -----------------------------------------------------------------------------

#[derive(Serialize)]
struct InfoReport<'a> {
    name: &'a str,
    url: &'a str,
    mandant_id: &'a str,
    workplace_id: &'a str,
    client_system_id: &'a str,
    user_id: Option<&'a str>,
    /// `basic` or `pkcs12`.
    credentials: &'static str,
    /// The TI environment the `.kon` file states.
    environment: Option<String>,
    product: &'a Product,
}

fn info(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let k = &session.dotkon;
    let r = InfoReport {
        name: &session.name,
        url: &k.url,
        mandant_id: &k.mandant_id,
        workplace_id: &k.workplace_id,
        client_system_id: &k.client_system_id,
        user_id: k.user_id.as_deref(),
        credentials: match k.credentials {
            Credentials::Basic { .. } => "basic",
            Credentials::Pkcs12 { .. } => "pkcs12",
        },
        environment: k.env.map(|e| e.to_string()),
        product: &session.connector.directory().product,
    };
    emit(out, Exit::Ok, &r, |doc| {
        let p = r.product;
        let context = format!("{}/{}/{}", r.mandant_id, r.workplace_id, r.client_system_id);
        doc.section("Connector");
        doc.field("name", Line::strong(r.name));
        doc.field("url", Line::code(r.url));
        doc.field(
            "context",
            Line::text(context).and_dim(" · mandant/workplace/client system"),
        );
        if let Some(user) = r.user_id {
            doc.field("user", user);
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

#[derive(Serialize)]
struct ServicesReport<'a> {
    product: &'a Product,
    services: Vec<ServiceInfo<'a>>,
}

#[derive(Serialize)]
struct ServiceInfo<'a> {
    name: &'a str,
    versions: Vec<VersionInfo<'a>>,
}

#[derive(Serialize)]
struct VersionInfo<'a> {
    version: &'a str,
    endpoint: Option<&'a str>,
    /// This tool calls this version.
    used: bool,
}

fn services(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let directory = session.connector.directory();
    let used: Vec<_> = BINDINGS
        .iter()
        .flat_map(|(service, versions)| versions.iter().map(move |v| (*service, *v)))
        .filter_map(|(service, v)| directory.resolve(service, &[v]).ok())
        .collect();
    let report = ServicesReport {
        product: &directory.product,
        services: directory
            .services
            .iter()
            .map(|s| ServiceInfo {
                name: &s.name,
                versions: s
                    .versions
                    .iter()
                    .map(|v| VersionInfo {
                        version: &v.version,
                        endpoint: v.endpoint_tls.as_deref().or(v.endpoint.as_deref()),
                        used: used
                            .iter()
                            .any(|b| b.service == s.name && b.version == v.version),
                    })
                    .collect(),
            })
            .collect(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.services.iter().flat_map(|s| {
            s.versions.iter().map(|v| {
                let used = if v.used {
                    Line::status(Tone::Good, "used")
                } else {
                    Line::text("")
                };
                vec![
                    Line::strong(s.name),
                    Line::code(v.version),
                    used,
                    cell(v.endpoint),
                ]
            })
        });
        doc.table(&["SERVICE", "VERSION", "", "ENDPOINT"], rows.collect());
    })
}

#[derive(Serialize)]
struct CardInfo {
    handle: String,
    card_type: &'static str,
    iccsn: Option<String>,
    /// The card terminal's `CtId`.
    terminal: String,
    slot: i64,
    holder: Option<String>,
    kvnr: Option<String>,
    inserted: String,
    certificate_expiration: Option<String>,
    /// `major.minor.revision` of the card's software.
    cos_version: Option<String>,
    object_system_version: Option<String>,
}

impl From<&Card> for CardInfo {
    fn from(c: &Card) -> Self {
        let v = |v: &ti_connector_client::types::VersionInfoType| {
            format!("{}.{}.{}", v.major, v.minor, v.revision)
        };
        CardInfo {
            handle: c.card_handle.clone(),
            card_type: c.card_type.as_str(),
            iccsn: c.iccsn.clone(),
            terminal: c.ct_id.clone(),
            slot: c.slot_id,
            holder: c.card_holder_name.clone(),
            kvnr: c.kvnr.clone(),
            inserted: c.insert_time.clone(),
            certificate_expiration: c.certificate_expiration_date.clone(),
            cos_version: c.card_version.as_ref().map(|cv| v(&cv.cos_version)),
            object_system_version: c
                .card_version
                .as_ref()
                .map(|cv| v(&cv.object_system_version)),
        }
    }
}

/// The table of `cards`.
fn card_table(doc: &mut Document, cards: &[&CardInfo]) {
    let rows = cards.iter().map(|c| {
        vec![
            Line::code(&c.handle),
            Line::strong(c.card_type),
            cell(c.iccsn.as_deref()),
            cell(c.holder.as_deref()),
        ]
    });
    let headings = ["HANDLE", "TYPE", "ICCSN", "HOLDER"];
    doc.table(&headings, rows.collect());
}

#[derive(Serialize)]
struct CardsReport {
    cards: Vec<CardInfo>,
}

fn cards(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let cards = call(session.connector.cards().list(&[]))?;
    let report = CardsReport {
        cards: cards.iter().map(CardInfo::from).collect(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        card_table(doc, &report.cards.iter().collect::<Vec<_>>());
        if report.cards.is_empty() {
            doc.paragraph(Line::dim("no card in the card terminals"));
        }
    })
}

#[derive(Serialize)]
struct CertificatesReport {
    card: CardInfo,
    certificates: Vec<CertificateInfo>,
}

#[derive(Serialize)]
struct CertificateInfo {
    cert_ref: &'static str,
    crypt: &'static str,
    subject: String,
    telematik_id: Option<String>,
    profession: Vec<String>,
    not_before: String,
    not_after: String,
    #[serde(skip)]
    not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    validity: &'static str,
    key: String,
    pem: String,
}

fn certificates(session: &Session, card: &str, out: &Output) -> Result<Exit, CliError> {
    let card = find(session, card)?;
    let certificates = session.connector.certificates();
    let read = card_call(
        &card,
        certificates.read_all(&card.card_handle, card.card_type),
    )?;
    let now = SystemClock.now();
    let report = CertificatesReport {
        card: CardInfo::from(&card),
        certificates: read
            .iter()
            .map(|c| CertificateInfo {
                cert_ref: c.cert_ref.as_str(),
                crypt: c.crypt.as_str(),
                subject: c.certificate.subject_cn().to_owned(),
                telematik_id: c.telematik_id().map(str::to_owned),
                profession: c
                    .admission
                    .iter()
                    .flat_map(|a| a.profession_items.clone())
                    .collect(),
                not_before: c.certificate.not_before().to_string(),
                not_after: c.certificate.not_after().to_string(),
                not_after_at: c.certificate.not_after(),
                validity: super::validity(&c.certificate, now),
                key: inspect::key_algorithm(&c.certificate, now),
                pem: pem(c.certificate.der()),
            })
            .collect(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.section("Card");
        card_table(doc, &[&report.card]);
        let rows = report.certificates.iter().map(|c| {
            let until = match c.validity {
                "valid" => Line::text(format!("until {}", date(c.not_after_at))),
                "expired" => Line::status(Tone::Bad, format!("expired {}", date(c.not_after_at))),
                _ => Line::status(Tone::Bad, "not yet valid"),
            };
            vec![
                Line::strong(c.cert_ref),
                Line::text(c.crypt),
                Line::text(&c.subject),
                Line::code(c.telematik_id.as_deref().unwrap_or("-")),
                until,
                Line::dim(&c.key),
            ]
        });
        doc.section("Certificates");
        doc.table(
            &[
                "REF",
                "KEY",
                "SUBJECT",
                "TELEMATIK-ID",
                "VALIDITY",
                "ALGORITHM",
            ],
            rows.collect(),
        );
        for c in &report.certificates {
            doc.pem(&c.pem);
        }
    })
}

#[derive(Serialize)]
struct StatusReport {
    vpn_ti: Option<VpnInfo>,
    vpn_sis: Option<VpnInfo>,
    errors: Vec<ErrorStateInfo>,
}

#[derive(Serialize)]
struct VpnInfo {
    status: String,
    since: String,
}

#[derive(Serialize)]
struct ErrorStateInfo {
    condition: String,
    severity: String,
    #[serde(rename = "type")]
    kind: String,
    active: bool,
    since: String,
}

fn status(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let state = call(session.connector.status())?.connector;
    let vpn = |status: &str, since: &str| VpnInfo {
        status: status.to_owned(),
        since: since.to_owned(),
    };
    let report = StatusReport {
        vpn_ti: state.as_ref().map(|s| {
            vpn(
                &s.vpn_ti_status.connection_status,
                &s.vpn_ti_status.timestamp,
            )
        }),
        vpn_sis: state.as_ref().map(|s| {
            vpn(
                &s.vpn_sis_status.connection_status,
                &s.vpn_sis_status.timestamp,
            )
        }),
        errors: state
            .into_iter()
            .flat_map(|s| s.operating_state.error_state)
            .map(|e| ErrorStateInfo {
                condition: e.error_condition,
                severity: e.severity,
                kind: e.r#type,
                active: e.value,
                since: e.valid_from,
            })
            .collect(),
    };
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
                    Line::status(Tone::Bad, &e.condition),
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

#[derive(Serialize)]
struct IdentitiesReport {
    identities: Vec<IdentityInfo>,
}

#[derive(Serialize)]
struct IdentityInfo {
    telematik_id: Option<String>,
    card_type: &'static str,
    holder: Option<String>,
    iccsn: Option<String>,
    handle: String,
}

fn identities(session: &Session, out: &Output) -> Result<Exit, CliError> {
    let cards = call(
        session
            .connector
            .cards()
            .list(&[CardType::Hba, CardType::SmcB]),
    )?;
    let certificates = session.connector.certificates();
    let identities = cards
        .iter()
        .map(|card| IdentityInfo {
            // A card whose C.AUT cannot be read is still listed, without an ID.
            telematik_id: block_on(certificates.read(
                &card.card_handle,
                Crypt::Ecc,
                &[CertRef::CAut],
            ))
            .ok()
            .and_then(|c| c.iter().find_map(|c| c.telematik_id().map(str::to_owned))),
            card_type: card.card_type.as_str(),
            holder: card.card_holder_name.clone(),
            iccsn: card.iccsn.clone(),
            handle: card.card_handle.clone(),
        })
        .collect();
    let report = IdentitiesReport { identities };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.identities.iter().map(|i| {
            vec![
                Line::code(i.telematik_id.as_deref().unwrap_or("-")),
                Line::strong(i.card_type),
                cell(i.holder.as_deref()),
                cell(i.iccsn.as_deref()),
                Line::code(&i.handle),
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
    certificates: Vec<ExpirationInfo>,
}

#[derive(Serialize)]
struct ExpirationInfo {
    terminal: String,
    handle: String,
    iccsn: String,
    subject: String,
    serial: String,
    /// The expiry date as the Konnektor states it.
    validity: String,
}

fn expiration(
    session: &Session,
    card: Option<&str>,
    crypt: CryptArg,
    out: &Output,
) -> Result<Exit, CliError> {
    let card = card.map(|card| find(session, card)).transpose()?;
    let handle = card.as_ref().map(|c| c.card_handle.as_str());
    let certificates = session.connector.certificates();
    let future = certificates.expiration(handle, crypt.into());
    let expiry = match &card {
        Some(card) => card_call(card, future)?,
        None => call(future)?,
    };
    let report = ExpirationReport {
        certificates: expiry
            .into_iter()
            .map(|e| ExpirationInfo {
                terminal: e.ct_id,
                handle: e.card_handle,
                iccsn: e.iccsn,
                subject: e.subject_common_name,
                serial: e.serial_number,
                validity: e.validity,
            })
            .collect(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        let rows = report.certificates.iter().map(|e| {
            vec![
                Line::strong(&e.validity),
                Line::text(&e.subject),
                Line::code(&e.iccsn),
                Line::text(&e.serial),
                Line::code(&e.handle),
            ]
        });
        doc.table(
            &["VALID UNTIL", "SUBJECT", "ICCSN", "SERIAL", "HANDLE"],
            rows.collect(),
        );
    })
}

// ---- describe ------------------------------------------------------------------------

#[derive(Serialize)]
struct CardReport {
    card: CardInfo,
}

fn describe_card(session: &Session, card: &str, out: &Output) -> Result<Exit, CliError> {
    let report = CardReport {
        card: CardInfo::from(&find(session, card)?),
    };
    emit(out, Exit::Ok, &report, |doc| {
        let c = &report.card;
        doc.section("Card");
        doc.field("type", Line::strong(c.card_type));
        doc.field("ICCSN", Line::code(c.iccsn.as_deref().unwrap_or("-")));
        if let Some(holder) = &c.holder {
            doc.field("holder", holder.as_str());
        }
        if let Some(kvnr) = &c.kvnr {
            doc.field("KVNR", Line::code(kvnr));
        }
        doc.field("terminal", format!("{} slot {}", c.terminal, c.slot));
        doc.field("inserted", c.inserted.as_str());
        if let Some(expiry) = &c.certificate_expiration {
            doc.field("certificates until", expiry.as_str());
        }
        if let (Some(cos), Some(os)) = (&c.cos_version, &c.object_system_version) {
            let os = format!(" · object system {os}");
            doc.field("versions", Line::text(format!("COS {cos}")).and_dim(os));
        }
        doc.field("handle", Line::code(&c.handle));
    })
}

// ---- verify and change ---------------------------------------------------------------

#[derive(Serialize)]
struct PinReport {
    card: CardInfo,
    pin: &'static str,
    /// `OK`, `REJECTED`, `WASBLOCKED`, `NOWBLOCKED`, `TRANSPORT_PIN` or `ERROR`.
    result: &'static str,
    left_tries: Option<i64>,
}

fn pin(
    session: &Session,
    args: &ConnectorArgs,
    pin: &PinArgs,
    change: bool,
    out: &Output,
) -> Result<Exit, CliError> {
    let card = find(session, &pin.card)?;
    let allowed = PinType::for_card(card.card_type);
    let pin_type = match (pin.pin, allowed) {
        (Some(p), _) if allowed.is_empty() || allowed.contains(&p) => p,
        (None, [only]) => *only,
        (named, _) => {
            let known: Vec<String> = allowed.iter().map(ToString::to_string).collect();
            let has = match known.as_slice() {
                [] => "no known PIN".to_owned(),
                known => known.join(", "),
            };
            let problem = named.map_or_else(|| "name one".to_owned(), |p| format!("not {p}"));
            return Err(CliError::PinType(format!(
                "{} has {has}; {problem}",
                card.card_type
            )));
        }
    };
    let verb = if change { "Change" } else { "Enter" };
    let message = format!("{verb} {pin_type} at the card terminal");
    let waiting = Waiting::start(&message, &card_label(&card), args.card_timeout);
    let pins = session.connector.pins();
    let response = if change {
        card_call(&card, pins.change(&card.card_handle, pin_type))
    } else {
        card_call(&card, pins.verify(&card.card_handle, pin_type))
    };
    drop(waiting);
    let response = response?;
    let accepted = response.pin_result == PinResult::Ok;
    let report = PinReport {
        card: CardInfo::from(&card),
        pin: pin_type.as_str(),
        result: response.pin_result.as_str(),
        left_tries: response.left_tries,
    };
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
        doc.field("card", card_label(&card));
    })
}

#[derive(Serialize)]
struct VerifyReport {
    source: String,
    subject: String,
    /// `VALID`, `INCONCLUSIVE` or `INVALID`.
    result: &'static str,
    /// The profession OIDs the Konnektor read from the certificate.
    roles: Vec<String>,
    /// The Konnektor's reason for a result other than `VALID`.
    errors: Vec<String>,
}

fn verify_certificate(
    session: &Session,
    source: &str,
    certificate: &Certificate,
    at: Option<Timestamp>,
    out: &Output,
) -> Result<Exit, CliError> {
    let verdict = call(
        session
            .connector
            .certificates()
            .verify(certificate.der(), at),
    )?;
    let status = verdict.verification_status;
    let result = status.verification_result;
    let report = VerifyReport {
        source: source.to_owned(),
        subject: certificate.subject_cn().to_owned(),
        result: result.as_str(),
        roles: verdict.role_list.role,
        errors: status
            .error
            .into_iter()
            .flat_map(|e| e.trace)
            .map(|t| format!("{} {}", t.code, t.error_text))
            .collect(),
    };
    let exit = if result == VerificationResult::Valid {
        Exit::Ok
    } else {
        Exit::Invalid
    };
    emit(out, exit, &report, |doc| {
        let tone = match result {
            VerificationResult::Valid => Tone::Good,
            VerificationResult::Inconclusive => Tone::Warn,
            VerificationResult::Invalid => Tone::Bad,
        };
        let what = " · the Konnektor's check: path and OCSP";
        doc.field("result", Line::status(tone, report.result).and_dim(what));
        let source = format!(" · {}", report.source);
        doc.field("certificate", Line::strong(&report.subject).and_dim(source));
        if let Some(at) = at {
            doc.field("at", date(at));
        }
        doc.items("roles", report.roles.iter().map(Line::code));
        doc.items(
            "errors",
            report.errors.iter().map(|e| Line::status(Tone::Bad, e)),
        );
    })
}
