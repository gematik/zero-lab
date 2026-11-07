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

//! `ti pki profiles list|describe`: the validation profiles and what they require.

use serde::Serialize;
use ti_client::pki::profiles::{self, Description};
use ti_pki::model::ValidationProfile;
use ti_pki::profile;

use crate::cli::{Environment, GlobalArgs};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Oid, Output, SCHEMA};

#[derive(Serialize)]
struct ListReport {
    schema: u32,
    profiles: Vec<ValidationProfile>,
}

#[derive(Serialize)]
struct DescribeReport<'a> {
    schema: u32,
    #[serde(flatten)]
    description: &'a Description,
}

pub fn list(out: &Output) -> Result<Exit, CliError> {
    let report = ListReport {
        schema: SCHEMA,
        profiles: profiles::list(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let rows = report.profiles.iter().map(|p| {
        let roles: Vec<&str> = p
            .required_role_oids
            .iter()
            .map(|o| o.name.unwrap_or(&o.oid))
            .collect();
        vec![
            Line::strong(p.name),
            codes(&p.accepts_types),
            codes(&p.default_for),
            Line::text(p.revocation),
            Line::text(if roles.is_empty() {
                "any".to_owned()
            } else {
                roles.join(", ")
            }),
            Line::dim(p.description),
        ]
    });
    let mut doc = Document::default();
    doc.table(
        &[
            "PROFILE",
            "TYPES",
            "DEFAULT FOR",
            "REVOCATION",
            "ROLES (ONE OF)",
            "DESCRIPTION",
        ],
        rows.collect(),
    );
    out.render(&doc)?;
    Ok(Exit::Ok)
}

pub fn describe(
    name: &str,
    env: Option<Environment>,
    offline: bool,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let p = profile::lookup(name).expect("clap only accepts registered profile names");
    let env = env.map(|env| super::concrete(env, global)).transpose()?;
    let description = profiles::describe(p, env, || crate::trust::session(global, offline, out))?;
    let report = DescribeReport {
        schema: SCHEMA,
        description: &description,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.title(format!("Profile {}", p.name))
        .paragraph(p.description)
        .field("revocation", description.profile.revocation)
        .field("default for", codes(&description.profile.default_for));
    for t in &description.types {
        doc.section(t.certificate_type)
            .field("key usage (all)", codes(&t.key_usage))
            .field("ext. usage (one of)", codes(&t.extended_key_usage))
            .items("policies (all)", t.policies.iter().map(oid_line))
            .items("roles (one of)", t.role_oids.iter().map(oid_line));
    }
    if let Some(tsl) = &description.tsl {
        doc.section(format!("TSL CAs · {}", tsl.environment));
        if tsl.cas.is_empty() {
            doc.paragraph(Line::dim("no CA of the TSL may issue these types"));
        }
        doc.table(
            &["CA", "PROVIDER", "TYPES"],
            tsl.cas
                .iter()
                .map(|ca| {
                    vec![
                        Line::strong(&ca.common_name),
                        Line::text(&ca.provider),
                        Line::text(ca.types.join(", ")),
                    ]
                })
                .collect(),
        );
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

fn oid_line(o: &Oid) -> Line {
    let line = Line::code(&o.oid);
    match o.name {
        Some(name) => line.and_dim(format!(" {name}")),
        None => line,
    }
}

/// Values as a comma-separated list of code spans; `none` for no values.
fn codes<T: AsRef<str>>(values: &[T]) -> Line {
    let mut line = Line::default();
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            line = line.and_text(", ");
        }
        line = line.and_code(value.as_ref());
    }
    if line.0.is_empty() {
        Line::dim("none")
    } else {
        line
    }
}
