//! Builds and validates a certificate chain against the TI roots: chain building, RFC 5280
//! path validation, type detection and the type's gemSpec_PKI baseline checks. No
//! revocation yet.
//!
//! ```console
//! cargo run -p ti-pki --example chain -- ee.pem [ca.pem ...]
//! cargo run -p ti-pki --example chain -- --tsl ECC-RSA_TSL.xml ee.pem
//! cargo run -p ti-pki --features dangerous-nonprod --example chain -- --env ref ee.pem ca.pem
//! ```
//!
//! The first certificate is the end entity; the others (in any order, several per file
//! allowed) are candidate intermediates. With `--tsl`, the TSL's CAs that a root signed
//! are candidates too.

use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::key::classify_key;
use ti_pki::tsl::{self, Tsl};
use ti_pki::{
    Certificate, CertificateCheck, CertificateType, Env, PathOptions, Timestamp, TrustConfig,
    build_chain, checks, detect_certificate_type, roots, validate_path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut env = Env::Prod;
    let mut tsl_path = None;
    loop {
        match args.first().map(String::as_str) {
            Some("--env") if args.len() > 1 => env = args[1].parse()?,
            Some("--tsl") if args.len() > 1 => tsl_path = Some(args[1].clone()),
            _ => break,
        }
        args.drain(..2);
    }
    if args.is_empty() {
        eprintln!("usage: chain [--env <env>] [--tsl <tsl.xml>] <end entity> [intermediates...]");
        std::process::exit(2);
    }
    let mut certs = Vec::new();
    for path in &args {
        let bytes = std::fs::read(path)?;
        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
            certs.extend(ti_pki::parse_pem_certificates(&bytes)?);
        } else {
            certs.push(Certificate::from_der(&bytes)?);
        }
    }
    let ee = certs.remove(0);
    let now = Timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());

    #[cfg(feature = "dangerous-nonprod")]
    let config = TrustConfig::preset(env);
    #[cfg(not(feature = "dangerous-nonprod"))]
    let config = if env.is_prod() {
        TrustConfig::preset_prod()
    } else {
        return Err(format!("{env} needs --features dangerous-nonprod").into());
    };
    let mut store = roots::load(&config, now)?.store();
    println!("environment   {env} ({} trusted roots)", store.len());
    if let Some(path) = tsl_path {
        let list = Tsl::parse(&std::fs::read(path)?)?;
        let matched = tsl::match_to_roots(list.intermediate_cas(), &store, &config.algorithms);
        println!(
            "tsl           #{}, {} CAs chain to the roots",
            list.sequence_number,
            matched.intermediates.len()
        );
        store = store.with_intermediates(matched.intermediates);
    }
    certs.extend(store.intermediates().iter().cloned());

    let t = detect_certificate_type(&ee);
    let (status, key) = classify_key(ee.public_key_info(), now);
    println!("end entity    {}", ee.subject_cn());
    println!(
        "type          {}",
        t.map_or("not detected".to_owned(), |t| t.to_string())
    );
    println!("key           {key} ({status})");

    let chain = match build_chain(&ee, &certs, &store) {
        Ok(chain) => chain,
        Err(e) => {
            let partial: Vec<&str> = e.partial.iter().map(Certificate::subject_cn).collect();
            println!("chain         incomplete after {}", partial.join(" -> "));
            println!("              {}", e.error);
            if let Some(last) = e.partial.last() {
                println!(
                    "hint          pass the issuing CA {:?} as a further argument \
                     or the environment's TSL with --tsl",
                    last.issuer_cn()
                );
            }
            return Ok(());
        }
    };
    let names: Vec<&str> = chain.iter().map(Certificate::subject_cn).collect();
    println!("chain         {}", names.join(" -> "));

    let ee_checks = t.map_or_else(Vec::new, baseline_checks);
    let result = validate_path(
        &chain,
        &PathOptions {
            now,
            algorithms: &config.algorithms,
            max_clock_skew: config.max_clock_skew,
            ee_checks: &ee_checks,
        },
    )?;
    println!(
        "path          {}",
        if result.valid { "valid" } else { "INVALID" }
    );
    for error in &result.errors {
        println!("  error       {error}");
    }
    Ok(())
}

/// The type's gemSpec_PKI baseline as end-entity checks.
fn baseline_checks(t: CertificateType) -> Vec<CertificateCheck> {
    let spec = t.spec();
    let mut ee_checks = vec![
        checks::key_usage(spec.key_usage),
        checks::certificate_policies(spec.policies),
        checks::role_oid(spec.role_oids),
    ];
    if !spec.ext_key_usage.is_empty() {
        ee_checks.push(checks::any_ext_key_usage(spec.ext_key_usage));
    }
    ee_checks
}
