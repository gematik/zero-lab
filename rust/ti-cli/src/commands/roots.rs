//! `ti pki roots list`: the roots an environment trusts, as the A_28419 walk from the
//! embedded anchor through roots.json yields them.

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::load::SystemClock;
use ti_pki::{Certificate, Clock, Timestamp, TrustConfig};

use crate::cli::{GlobalArgs, RootsArgs};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA, Tone, hex, pem};
use crate::trust::{Session, TrustInfo};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    environment: &'static str,
    trust: TrustInfo,
    insecure_transport: bool,
    roots: Vec<RootInfo>,
}

#[derive(Serialize)]
struct RootInfo {
    common_name: String,
    subject: String,
    not_before: String,
    not_after: String,
    #[serde(skip)]
    not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    validity: &'static str,
    /// The embedded anchor the walk started from.
    anchor: bool,
    /// The key, e.g. `ECDSA brainpoolP256r1`.
    key: String,
    sha256: String,
    pem: String,
}

/// Runs `ti pki roots list`.
pub fn list(args: &RootsArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let (trust, env) = (&args.trust, super::concrete(args.trust.env, global)?);
    let config = super::trust_config(env, args.nist_only);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, trust.offline, out)?;
    let material = session.load(&config, env.tier(), trust.at)?;
    let now = trust.at.unwrap_or_else(|| SystemClock.now());
    let report = Report {
        schema: SCHEMA,
        environment: env.as_str(),
        roots: material
            .store
            .roots()
            .iter()
            .map(|root| describe(root, &config, now))
            .collect(),
        trust: material.info,
        insecure_transport: session.insecure,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report))?;
    }
    Ok(Exit::Ok)
}

fn describe(root: &Certificate, config: &TrustConfig, now: Timestamp) -> RootInfo {
    RootInfo {
        common_name: root.subject_cn().to_owned(),
        subject: root.subject().to_string(),
        not_before: root.not_before().to_string(),
        not_after: root.not_after().to_string(),
        not_after_at: root.not_after(),
        validity: super::validity(root, now),
        anchor: root.der() == &*config.anchor,
        key: super::inspect::key_algorithm(root, now),
        sha256: hex(&Sha256::digest(root.der())),
        pem: pem(root.der()),
    }
}

fn document(report: &Report) -> Document {
    let mut doc = Document::default();
    doc.paragraph(
        Line::strong(format!("{} roots", report.roots.len()))
            .and_text(format!(" · {}", report.environment)),
    );
    doc.paragraph(Line::dim("trust ").and_line(super::trust_line(&report.trust)));
    // By generation (GEM.RCA2 … GEM.RCA11), not in the order the walk reached them.
    let mut roots: Vec<&RootInfo> = report.roots.iter().collect();
    roots.sort_by_key(|root| generation(&root.common_name));
    let rows = roots.into_iter().map(|root| {
        vec![
            Line::strong(&root.common_name),
            Line::text(super::organization(&root.subject).unwrap_or_else(|| "-".to_owned())),
            Line::text(&root.key),
            super::validity_cell(root.not_after_at, root.validity),
            if root.anchor {
                Line::status(Tone::Good, "anchor")
            } else {
                Line::text("")
            },
        ]
    });
    doc.table(
        &["ROOT", "ORGANIZATION", "KEY", "VALIDITY", ""],
        rows.collect(),
    );
    doc
}

/// The name with its first number as a number, so `RCA10` sorts after `RCA9`.
pub(super) fn generation(name: &str) -> (String, u64, String) {
    let start = name
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(name.len());
    let digits = name[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(name.len(), |n| start + n);
    (
        name[..start].to_owned(),
        name[start..digits].parse().unwrap_or(0),
        name[digits..].to_owned(),
    )
}
