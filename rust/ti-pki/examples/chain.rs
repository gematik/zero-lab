//! Builds and validates a certificate chain against the TI roots: chain building, RFC 5280
//! path validation, type detection and the type's gemSpec_PKI baseline checks. No
//! revocation yet.
//!
//! ```console
//! cargo run -p ti-pki --example chain -- ee.pem [ca.pem ...]
//! cargo run -p ti-pki --features dangerous-nonprod --example chain -- --env ref ee.pem ca.pem
//! ```
//!
//! The first certificate is the end entity; the others (in any order, several per file
//! allowed) are candidate intermediates, e.g. the issuing CA from the TSL.

use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::key::classify_key;
use ti_pki::{
    Certificate, CertificateCheck, Env, PathOptions, Timestamp, TrustConfig, build_chain, checks,
    detect_certificate_type, roots, validate_path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut env = Env::Prod;
    if args.first().map(String::as_str) == Some("--env") && args.len() > 1 {
        env = args[1].parse()?;
        args.drain(..2);
    }
    if args.is_empty() {
        eprintln!("usage: chain [--env <env>] <end entity> [intermediates...]");
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
    let store = roots::load(&config, now)?.store();
    println!("environment   {env} ({} trusted roots)", store.len());

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
                    "hint          pass the issuing CA {:?} as a further argument; \
                     intermediates only come from the TSL once that is ported",
                    last.issuer_cn()
                );
            }
            return Ok(());
        }
    };
    let names: Vec<&str> = chain.iter().map(Certificate::subject_cn).collect();
    println!("chain         {}", names.join(" -> "));

    let ee_checks: Vec<CertificateCheck> = t.map_or_else(Vec::new, |t| {
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
    });
    let result = validate_path(
        &chain,
        &PathOptions {
            now,
            algorithms: &config.algorithms,
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
