//! `ti pki roots bundle` and `ti pki tsl bundle`: verified certificates as a CA bundle,
//! the input other tools take for trust. PEM by default, what curl `--cacert`, openssl
//! `-CAfile`, Go and rustls read; with `--p12` a PKCS#12 truststore for Java, each
//! certificate a `trustedCertEntry` (the bag attributes OpenSSL's `-caname` and
//! `-jdktrust anyExtendedKeyUsage` write).

use std::io::{IsTerminal as _, Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pkcs12::{CertificateBag, Pkcs12, oids};
use ti_pki::{Certificate, Timestamp};

use crate::cli::{BundleArgs, GlobalArgs, RootsBundleArgs};
use crate::error::{CliError, Exit};
use crate::output::document::date;
use crate::output::{Document, Line, Output, hex, pem};
use crate::trust::{Session, TrustInfo};

/// The JSON document; `schema` is added on output.
#[derive(Serialize)]
pub(super) struct Report {
    environment: &'static str,
    /// `pem` or `p12`.
    format: &'static str,
    certificates: Vec<Entry>,
    /// The file written; absent when the bundle went to stdout.
    output: Option<String>,
    /// The sequence number of the TSL the CAs come from; `tsl bundle` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    tsl_sequence_number: Option<u64>,
    trust: TrustInfo,
    insecure_transport: bool,
}

#[derive(Serialize)]
struct Entry {
    common_name: String,
    not_after: String,
    #[serde(skip)]
    not_after_at: Timestamp,
    sha256: String,
    /// The truststore alias; `p12` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    /// The certificate; PEM bundles reported as JSON instead of written, only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pem: Option<String>,
}

/// What a bundle command found, before it is written.
pub(super) struct Found {
    pub environment: &'static str,
    pub certificates: Vec<Certificate>,
    pub tsl_sequence_number: Option<u64>,
    pub trust: TrustInfo,
    pub insecure_transport: bool,
}

/// Runs `ti pki roots bundle`: the roots `roots list` shows, oldest generation first.
pub fn roots(args: &RootsBundleArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    refuse_existing(&args.bundle)?;
    let roots = &args.roots;
    let env = super::concrete(roots.trust.env, global)?;
    let config = super::trust_config(env, roots.nist_only);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, roots.trust.offline, out)?;
    let material = session.load(&config, env.tier(), roots.trust.at)?;
    let mut certificates = material.store.roots().to_vec();
    certificates.sort_by_key(|root| super::roots::generation(root.subject_cn()));
    write(
        Found {
            environment: env.as_str(),
            certificates,
            tsl_sequence_number: None,
            trust: material.info,
            insecure_transport: session.insecure,
        },
        &args.bundle,
        out,
    )
}

/// Refuses an existing `-o` file before any download.
pub(super) fn refuse_existing(args: &BundleArgs) -> Result<(), CliError> {
    match &args.output {
        Some(path) if !args.force && path.exists() => {
            Err(CliError::OutputExists(path.display().to_string()))
        }
        _ => Ok(()),
    }
}

/// Writes `found` as `args` asks: to `-o`, else to stdout unless the output format is
/// JSON, which reports instead (with each PEM, when nothing was written).
pub(super) fn write(found: Found, args: &BundleArgs, out: &Output) -> Result<Exit, CliError> {
    if found.certificates.is_empty() {
        return Err(CliError::NoCertificate {
            source_name: "the trust material, filtered".into(),
        });
    }
    let aliases = args.p12.then(|| aliases(&found.certificates));
    let bytes = match (&aliases, &args.p12_password) {
        (Some(aliases), Some(password)) => truststore(&found.certificates, aliases, password)?,
        _ => found
            .certificates
            .iter()
            .map(|c| pem(c.der()))
            .collect::<String>()
            .into_bytes(),
    };
    if let Some(path) = &args.output {
        super::write_file(path, &bytes, args.force, false)?;
    } else if !out.is_json() {
        if args.p12 && std::io::stdout().is_terminal() {
            return Err(CliError::Output(std::io::Error::other(
                "a PKCS#12 truststore is binary: pass -o FILE or redirect stdout",
            )));
        }
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        return Ok(Exit::Ok);
    }
    let with_pem = !args.p12 && args.output.is_none();
    let report = Report {
        environment: found.environment,
        format: if args.p12 { "p12" } else { "pem" },
        certificates: found
            .certificates
            .iter()
            .enumerate()
            .map(|(i, c)| Entry {
                common_name: c.subject_cn().to_owned(),
                not_after: c.not_after().to_string(),
                not_after_at: c.not_after(),
                sha256: hex(&Sha256::digest(c.der())),
                alias: aliases.as_ref().map(|a| a[i].clone()),
                pem: with_pem.then(|| pem(c.der())),
            })
            .collect(),
        output: args.output.as_ref().map(|p| p.display().to_string()),
        tsl_sequence_number: found.tsl_sequence_number,
        trust: found.trust,
        insecure_transport: found.insecure_transport,
    };
    super::connector::emit(out, Exit::Ok, &report, |doc| view(doc, &report))
}

fn view(doc: &mut Document, report: &Report) {
    let format = match report.format {
        "p12" => "PKCS#12 truststore",
        _ => "PEM",
    };
    doc.paragraph(
        Line::strong(format!("{} certificates", report.certificates.len()))
            .and_text(format!(" · {format} · {}", report.environment)),
    );
    doc.paragraph(Line::dim("trust ").and_line(super::trust_line(&report.trust)));
    let rows = report.certificates.iter().map(|c| {
        let mut row = vec![
            Line::strong(&c.common_name),
            Line::text(date(c.not_after_at)),
        ];
        if let Some(alias) = &c.alias {
            row.push(Line::code(alias));
        }
        row
    });
    let headers: &[&str] = if report.format == "p12" {
        &["CERTIFICATE", "NOT AFTER", "ALIAS"]
    } else {
        &["CERTIFICATE", "NOT AFTER"]
    };
    doc.table(headers, rows.collect());
    if let Some(output) = &report.output {
        doc.field("to", Line::code(output));
    }
}

/// Java's alias of each certificate: its common name in lower case, as keytool shows
/// aliases, made unique with `-2`, `-3`, … in order.
fn aliases(certificates: &[Certificate]) -> Vec<String> {
    let mut taken: Vec<String> = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        let base = certificate.subject_cn().to_lowercase();
        let mut alias = base.clone();
        let mut n = 2;
        while taken.contains(&alias) {
            alias = format!("{base}-{n}");
            n += 1;
        }
        taken.push(alias);
    }
    taken
}

fn truststore(
    certificates: &[Certificate],
    aliases: &[String],
    password: &str,
) -> Result<Vec<u8>, CliError> {
    let p12 = Pkcs12 {
        certificates: certificates
            .iter()
            .zip(aliases)
            .map(|(certificate, alias)| CertificateBag {
                der: certificate.der().to_vec(),
                friendly_name: Some(alias.clone()),
                local_key_id: None,
                trusted_key_usage: Some(oids::ANY_EXTENDED_KEY_USAGE),
            })
            .collect(),
        ..Pkcs12::default()
    };
    super::pkcs12::encode(&p12, password, "truststore")
}
