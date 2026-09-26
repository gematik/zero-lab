//! Validates a certificate the way `ti pki verify` does: trust domain, profile, chain
//! through the TSL's intermediates, path, key and OCSP for the end entity and every CA.
//!
//! ```console
//! cargo run -p ti-pki --features reqwest,os --example validate -- --tsl ECC-RSA_TSL.xml ee.pem
//! cargo run -p ti-pki --features reqwest,os,dangerous-nonprod --example validate -- \
//!     --tsl ECC-RSA_TSL-ref.xml ee.pem
//! ```
//!
//! Options: `--env auto|prod|ref|test|dev` (default `auto`: detected from the
//! certificates), `--profile auto|none|<name>` (default `auto`), `--tsl <file>`,
//! `--revocation hard|soft|off` (default: the environment's). The first certificate is
//! the end entity, the others are candidate intermediates. Exits with 1 when invalid.

use std::sync::Arc;

use ti_pki::load::SystemClock;
use ti_pki::ocsp::OcspChecker;
use ti_pki::profile::{self, SelectReason};
use ti_pki::reqwest::ReqwestTransport;
use ti_pki::revocation::RevocationMode;
use ti_pki::trustdomain::detect_trust_domain;
use ti_pki::tsl::{self, Tsl};
use ti_pki::{
    Certificate, Clock, Env, Tier, Timestamp, TrustConfig, TrustStore, ValidationResult, Validator,
    detect_certificate_type, roots,
};

struct Options {
    env: Option<Env>,
    profile: String,
    tsl: Option<String>,
    revocation: Option<RevocationMode>,
    files: Vec<String>,
}

fn options() -> Result<Options, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        env: None,
        profile: profile::AUTO.into(),
        tsl: None,
        revocation: None,
        files: Vec::new(),
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--env" => {
                let env = value()?;
                options.env = if env == "auto" {
                    None
                } else {
                    Some(env.parse()?)
                };
            }
            "--profile" => options.profile = value()?,
            "--tsl" => options.tsl = Some(value()?),
            "--revocation" => {
                options.revocation = Some(match value()?.as_str() {
                    "hard" => RevocationMode::HardFail,
                    "soft" => RevocationMode::SoftFail,
                    "off" => RevocationMode::Disabled,
                    other => return Err(format!("unknown revocation mode {other}").into()),
                });
            }
            _ => options.files.push(arg),
        }
    }
    if options.files.is_empty() {
        return Err(format!(
            "usage: validate [--env auto|<env>] [--profile {}] [--tsl <file>] \
             [--revocation hard|soft|off] <certificate> [intermediates...]",
            profile::selector_values().join("|")
        )
        .into());
    }
    Ok(options)
}

fn read_certificates(files: &[String]) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let mut certs = Vec::new();
    for path in files {
        let bytes = std::fs::read(path)?;
        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
            certs.extend(ti_pki::parse_pem_certificates(&bytes)?);
        } else {
            certs.push(Certificate::from_der(&bytes)?);
        }
    }
    Ok(certs)
}

#[cfg_attr(
    feature = "dangerous-nonprod",
    allow(clippy::unnecessary_wraps, reason = "fails without dangerous-nonprod")
)]
fn preset(env: Env) -> Result<TrustConfig, Box<dyn std::error::Error>> {
    #[cfg(feature = "dangerous-nonprod")]
    return Ok(TrustConfig::preset(env));
    #[cfg(not(feature = "dangerous-nonprod"))]
    if env.is_prod() {
        Ok(TrustConfig::preset_prod())
    } else {
        Err(format!("{env} needs --features dangerous-nonprod").into())
    }
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let options = options()?;
    let certs = read_certificates(&options.files)?;
    let now = SystemClock.now();

    let env = if let Some(env) = options.env {
        env
    } else {
        detect_env(&certs, now)?
    };
    let mut config = preset(env)?;
    if let Some(revocation) = options.revocation {
        config.revocation = revocation;
    }
    config.validate(env.tier())?;
    println!("environment   {env} (revocation {:?})", config.revocation);

    let mut store = roots::load(&config, now)?.store();
    if let Some(path) = &options.tsl {
        let list = Tsl::parse(&std::fs::read(path)?)?;
        let matched = tsl::match_to_roots(list.intermediate_cas(), &store, &config.algorithms);
        println!(
            "tsl           #{}, {} CAs chain to the {} roots",
            list.sequence_number,
            matched.intermediates.len(),
            store.len()
        );
        store = store.with_intermediates(matched.intermediates);
    }

    let validator = choose_validator(&options.profile, &config, Arc::new(store), &certs[0])?;
    let transport = ReqwestTransport::new(reqwest::Client::new());
    let checker = OcspChecker::new(&config, transport, SystemClock);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(validator.validate(&certs, now, &checker))?;
    print_result(&result);
    Ok(result.valid)
}

fn detect_env(certs: &[Certificate], now: Timestamp) -> Result<Env, Box<dyn std::error::Error>> {
    let domain = detect_trust_domain(certs, now);
    let tier = match domain.domain {
        Some(Tier::Prod) => "prod",
        Some(Tier::NonProd) => "non-prod",
        None => "undecided",
    };
    let detail = if domain.detail.is_empty() {
        "no evidence"
    } else {
        &domain.detail
    };
    println!(
        "trust domain  {tier} ({}: {detail})",
        domain.method.map_or("-", |m| m.as_str())
    );
    match domain.domain {
        Some(Tier::Prod) => Ok(Env::Prod),
        // ref and test share their roots; ref is the one the TSL usually comes from.
        Some(Tier::NonProd) => Ok(Env::Ref),
        None => Err("trust domain undecided; pass --env".into()),
    }
}

fn choose_validator(
    selector: &str,
    config: &TrustConfig,
    store: Arc<TrustStore>,
    ee: &Certificate,
) -> Result<Validator, Box<dyn std::error::Error>> {
    let cert_type = detect_certificate_type(ee);
    println!("end entity    {}", ee.subject_cn());
    println!(
        "type          {}",
        cert_type.map_or("not detected".to_owned(), |t| t.to_string())
    );
    if selector == profile::NONE {
        println!("profile       none (chain only)");
        return Ok(Validator::new(config, store));
    }
    if selector == profile::AUTO {
        let selection = profile::select_for_cert(ee);
        let (Some(p), Some(t)) = (selection.profile, selection.cert_type) else {
            let code = if selection.reason == SelectReason::Ambiguous {
                "profile_ambiguous"
            } else {
                "profile_not_detected"
            };
            println!(
                "profile       none, {code}: {} (chain only)",
                selection.detail
            );
            return Ok(Validator::new(config, store));
        };
        println!(
            "profile       {p} ({}: {})",
            selection.reason, selection.detail
        );
        return Ok(p.validator(config, store, t));
    }
    let p = profile::lookup(selector).ok_or(format!("unknown profile {selector}"))?;
    let Some(t) = cert_type else {
        println!("profile       {p} (forced; type unknown, roles only)");
        return Ok(Validator {
            required_role_oids: p.required_role_oids.to_vec(),
            revocation: p.revocation_mode(config),
            ..Validator::new(config, store)
        });
    };
    if !p.accepts(t) {
        println!("warning       profile_type_mismatch: {p} does not accept {t}");
    }
    println!("profile       {p} (forced)");
    Ok(p.validator(config, store, t))
}

fn print_result(result: &ValidationResult) {
    println!();
    for (cert, detail) in result.chain.iter().zip(&result.cert_results) {
        let revocation = detail.revocation.as_ref().map_or(String::new(), |r| {
            format!(", OCSP {} by {}", r.status, or_dash(&r.responder_name))
        });
        println!(
            "  {:<11} {}{revocation}",
            detail.position.as_str(),
            cert.subject_cn()
        );
    }
    println!();
    for error in &result.errors {
        println!("error         {error}");
    }
    for warning in &result.warnings {
        println!("warning       {warning}");
    }
    println!(
        "result        {}",
        if result.valid { "VALID" } else { "INVALID" }
    );
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}
