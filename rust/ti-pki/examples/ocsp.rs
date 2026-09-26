//! Checks a certificate's revocation status by OCSP, link by link: the end entity at
//! its CA's responder and every CA at its root's responder, each verdict as the
//! revocation table decides it under HardFail.
//!
//! ```console
//! cargo run -p ti-pki --features reqwest,os --example ocsp -- --tsl ECC-RSA_TSL.xml ee.pem
//! cargo run -p ti-pki --features reqwest,os,dangerous-nonprod --example ocsp -- \
//!     --env ref ca.pem root.pem
//! ```
//!
//! As in the `chain` example, the first certificate is the one checked and the others
//! are candidate intermediates; `--tsl` adds the TSL's CAs that chain to the roots.

use ti_pki::load::SystemClock;
use ti_pki::ocsp::OcspChecker;
use ti_pki::reqwest::ReqwestTransport;
use ti_pki::revocation::{
    ResponderAuthorization, RevocationChecker, RevocationFinding, RevocationMode, RevocationStatus,
    apply_revocation,
};
use ti_pki::time::Clock;
use ti_pki::tsl::{self, Tsl};
use ti_pki::{Certificate, Env, TrustConfig, build_chain, roots};

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
        eprintln!("usage: ocsp [--env <env>] [--tsl <tsl.xml>] <certificate> [intermediates...]");
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
    let leaf = certs.remove(0);

    #[cfg(feature = "dangerous-nonprod")]
    let config = TrustConfig::preset(env);
    #[cfg(not(feature = "dangerous-nonprod"))]
    let config = if env.is_prod() {
        TrustConfig::preset_prod()
    } else {
        return Err(format!("{env} needs --features dangerous-nonprod").into());
    };
    let mut store = roots::load(&config, SystemClock.now())?.store();
    if let Some(path) = tsl_path {
        let list = Tsl::parse(&std::fs::read(path)?)?;
        let matched = tsl::match_to_roots(list.intermediate_cas(), &store, &config.algorithms);
        store = store.with_intermediates(matched.intermediates);
    }
    certs.extend(store.intermediates().iter().cloned());
    let chain = match build_chain(&leaf, &certs, &store) {
        Ok(chain) => chain,
        Err(e) => {
            println!("chain         incomplete: {}", e.error);
            return Ok(());
        }
    };
    let names: Vec<&str> = chain.iter().map(Certificate::subject_cn).collect();
    println!("environment   {env}");
    println!("chain         {}", names.join(" -> "));

    let transport = ReqwestTransport::new(reqwest::Client::new());
    let checker = OcspChecker::new(&config, transport, SystemClock);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for link in chain.windows(2) {
        let (cert, issuer) = (&link[0], &link[1]);
        println!();
        println!("certificate   {}", cert.subject_cn());
        let outcome = runtime.block_on(checker.check(cert, issuer, &store));
        match &outcome {
            Ok(result) => {
                println!("responder     {}", or_dash(&result.responder_url));
                println!("status        {}", result.status);
                if result.status != RevocationStatus::Good {
                    println!("reason        {}", result.reason);
                }
                if let Some(revoked_at) = result.revoked_at {
                    println!("revoked at    {revoked_at}");
                }
                if !result.responder_name.is_empty() {
                    let kind = match &result.authorization {
                        Some(ResponderAuthorization::Issuer) => "the CA".to_owned(),
                        Some(ResponderAuthorization::SameTspDelegate { ca, tsp }) => format!(
                            "delegate of {ca}, same TSP {tsp:?}; WARNING: not RFC 6960 conform"
                        ),
                        _ => "delegate".to_owned(),
                    };
                    println!("signed by     {} ({kind})", result.responder_name);
                }
                if let Some(produced_at) = result.produced_at {
                    println!("produced at   {produced_at}");
                }
            }
            Err(error) => println!("check failed  {error}"),
        }
        let verdict = match apply_revocation(RevocationMode::HardFail, cert.subject_cn(), &outcome)
        {
            None => "accepted".to_owned(),
            Some(RevocationFinding::Error(e)) => format!("REJECTED ({})", e.code),
            Some(RevocationFinding::Warning(w)) => format!("accepted with warning ({})", w.code),
        };
        println!("verdict       {verdict}");
    }
    Ok(())
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}
