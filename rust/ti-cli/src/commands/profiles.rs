//! `ti pki profiles list|describe`: the validation profiles and what they require.

use serde::Serialize;
use ti_pki::profile::{self, Profile};
use ti_pki::revocation::RevocationMode;
use ti_pki::{CertificateType, checks};

use crate::error::{CliError, Exit};
use crate::output::{Document, Line, OidInfo, Output, SCHEMA};

#[derive(Serialize)]
struct ListReport {
    schema: u32,
    profiles: Vec<ProfileInfo>,
}

#[derive(Serialize)]
struct DescribeReport {
    schema: u32,
    profile: ProfileInfo,
    /// The baseline each accepted type imposes, with the profile's overlay applied.
    types: Vec<TypeRequirements>,
}

#[derive(Serialize)]
struct ProfileInfo {
    name: &'static str,
    description: &'static str,
    revocation: &'static str,
    accepts_types: Vec<&'static str>,
    default_for: Vec<&'static str>,
    required_role_oids: Vec<OidInfo>,
}

#[derive(Serialize)]
struct TypeRequirements {
    certificate_type: &'static str,
    key_usage: Vec<&'static str>,
    extended_key_usage: Vec<String>,
    policies: Vec<OidInfo>,
    /// One of these must be asserted; empty for no requirement.
    role_oids: Vec<OidInfo>,
}

fn revocation(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}

fn info(p: &Profile) -> ProfileInfo {
    ProfileInfo {
        name: p.name,
        description: p.description,
        revocation: revocation(p.revocation),
        accepts_types: p.accepts_types.iter().map(|t| t.as_str()).collect(),
        default_for: p.default_for.iter().map(|t| t.as_str()).collect(),
        required_role_oids: p.required_role_oids.iter().map(OidInfo::new).collect(),
    }
}

fn requirements(p: &Profile, t: CertificateType) -> TypeRequirements {
    let spec = t.spec();
    TypeRequirements {
        certificate_type: t.as_str(),
        key_usage: spec
            .key_usage
            .iter()
            .map(|bit| checks::key_usage_name(*bit))
            .collect(),
        extended_key_usage: spec
            .ext_key_usage
            .iter()
            .map(checks::ext_key_usage_name)
            .collect(),
        policies: spec
            .policies
            .iter()
            .chain(p.extra_policies)
            .map(OidInfo::new)
            .collect(),
        role_oids: p.effective_role_oids(t).iter().map(OidInfo::new).collect(),
    }
}

pub fn list(out: &Output) -> Result<Exit, CliError> {
    let report = ListReport {
        schema: SCHEMA,
        profiles: profile::PROFILES.iter().map(|p| info(p)).collect(),
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

pub fn describe(name: &str, out: &Output) -> Result<Exit, CliError> {
    let p = profile::lookup(name).expect("clap only accepts registered profile names");
    let report = DescribeReport {
        schema: SCHEMA,
        profile: info(p),
        types: p
            .accepts_types
            .iter()
            .map(|t| requirements(p, *t))
            .collect(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.title(format!("Profile {}", p.name))
        .paragraph(p.description)
        .field("revocation", report.profile.revocation)
        .field("default for", codes(&report.profile.default_for));
    for t in &report.types {
        doc.section(t.certificate_type)
            .field("key usage (all)", codes(&t.key_usage))
            .field("ext. usage (one of)", codes(&t.extended_key_usage))
            .items("policies (all)", t.policies.iter().map(oid_line))
            .items("roles (one of)", t.role_oids.iter().map(oid_line));
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

fn oid_line(o: &OidInfo) -> Line {
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
