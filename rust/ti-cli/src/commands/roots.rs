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

//! `ti pki roots list`: the roots an environment trusts, as the A_28419 walk from the
//! embedded anchor through roots.json yields them.

use serde::Serialize;
use ti_client::pki::roots::{self as engine, RootInfo, Roots};

use crate::cli::{GlobalArgs, RootsArgs};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    #[serde(flatten)]
    roots: Roots,
}

/// Runs `ti pki roots list`.
pub fn list(args: &RootsArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let (trust, env) = (&args.trust, super::concrete(args.trust.env, global)?);
    let session = crate::trust::session(global, trust.offline, out)?;
    let report = Report {
        schema: SCHEMA,
        roots: engine::list(&session, env, args.nist_only, trust.at)?,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report.roots))?;
    }
    Ok(Exit::Ok)
}

fn document(report: &Roots) -> Document {
    let mut doc = Document::default();
    doc.paragraph(
        Line::strong(format!("{} roots", report.roots.len()))
            .and_text(format!(" · {}", report.environment)),
    );
    doc.paragraph(Line::dim("trust ").and_line(super::trust_line(&report.trust)));
    // By generation (GEM.RCA2 … GEM.RCA11), not in the order the walk reached them.
    let mut roots: Vec<&RootInfo> = report.roots.iter().collect();
    roots.sort_by_key(|root| engine::generation(&root.common_name));
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
