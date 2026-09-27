//! `ti pki roots list`: the roots an environment trusts, as the A_28419 walk from the
//! embedded anchor through roots.json yields them.

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::load::SystemClock;
use ti_pki::{Certificate, Clock, Timestamp, TrustConfig};

use crate::cli::{GlobalArgs, TrustArgs};
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
    sha256: String,
    pem: String,
}

/// Runs `ti pki roots list`.
pub fn list(args: &TrustArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let env = super::concrete(args.env)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, args.offline, out)?;
    let material = session.load(&config, env.tier())?;
    let now = SystemClock.now();
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
    doc.items(
        "",
        report.roots.iter().map(|root| {
            let mut line = Line::strong(&root.common_name)
                .and_line(super::expiry(root.not_after_at, root.validity));
            if root.anchor {
                line = line.and_text(" · ").and_status(Tone::Good, "anchor");
            }
            line
        }),
    );
    doc
}
