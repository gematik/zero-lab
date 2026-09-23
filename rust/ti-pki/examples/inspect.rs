//! Prints what `ti-pki` reads from certificates, and checks which of them signed which.
//!
//! ```console
//! cargo run -p ti-pki --example inspect -- chain.pem [more.pem|cert.der ...]
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::key::classify_key;
use ti_pki::{Certificate, Timestamp, algorithms, oid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: inspect <certificate file (PEM or DER)>...");
        std::process::exit(2);
    }
    let mut certs = Vec::new();
    for path in &paths {
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"-----") || bytes.windows(11).any(|w| w == b"-----BEGIN ") {
            certs.extend(ti_pki::parse_pem_certificates(&bytes)?);
        } else {
            certs.push(Certificate::from_der(&bytes)?);
        }
    }
    let now = Timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    for cert in &certs {
        print_cert(cert, &certs, now)?;
    }
    Ok(())
}

fn print_cert(
    cert: &Certificate,
    all: &[Certificate],
    now: Timestamp,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("== {}", cert.subject_cn());
    println!("subject       {}", cert.subject());
    println!("issuer        {}", cert.issuer());
    println!("serial        {}", hex(cert.serial()));
    let state = if now < cert.not_before() {
        "not yet valid"
    } else if now > cert.not_after() {
        "expired"
    } else {
        "valid now"
    };
    println!(
        "validity      {} .. {} ({state})",
        cert.not_before(),
        cert.not_after()
    );
    let (status, key) = classify_key(cert.public_key_info(), now);
    println!("key           {key} ({status})");
    if let Some(ku) = cert.key_usage() {
        let flags: Vec<String> = ku.0.into_iter().map(|f| format!("{f:?}")).collect();
        println!("key usage     {}", flags.join(", "));
    }
    for eku in cert.ext_key_usage() {
        println!("ext key usage {eku}");
    }
    if let Some(bc) = cert.basic_constraints() {
        println!(
            "basic constr  ca={} path_len={:?}",
            bc.ca, bc.path_len_constraint
        );
    }
    for policy in cert.policies() {
        println!("policy        {}", oid::format(policy));
    }
    for url in cert.ocsp_urls() {
        println!("ocsp          {url}");
    }
    if let Some(ski) = cert.subject_key_id() {
        println!("ski           {}", hex(ski));
    }
    if let Some(aki) = cert.authority_key_id() {
        println!("aki           {}", hex(aki));
    }
    if let Some(admission) = cert.admission()? {
        println!("admission     {}", admission.profession_items.join(", "));
        for profession in &admission.profession_oids {
            println!("  role        {}", oid::format(profession));
        }
        if let Some(number) = &admission.registration_number {
            println!("  reg. number {number}");
        }
    }
    let issuers: Vec<&Certificate> = all
        .iter()
        .filter(|c| c.subject_der() == cert.issuer_der())
        .collect();
    if issuers.is_empty() {
        println!("signature     issuer not among the inputs");
    }
    for issuer in issuers {
        let verdict = match algorithms::find(
            algorithms::DEFAULT,
            &issuer.public_key_alg_id(),
            &cert.signature_alg_id(),
        ) {
            None => "no algorithm for this key/signature pair".to_owned(),
            Some(alg) => {
                match alg.verify_signature(issuer.public_key(), cert.tbs_der(), cert.signature()) {
                    Ok(()) => format!("verified ({alg:?})"),
                    Err(_) => format!("INVALID ({alg:?})"),
                }
            }
        };
        println!("signed by     {}: {verdict}", issuer.subject_cn());
    }
    println!();
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
