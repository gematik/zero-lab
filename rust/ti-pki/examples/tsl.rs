//! Reads a TSL and matches its CAs to the environment's roots: what the TSL contributes
//! to a trust store. The list is read unverified here (see the `tsl_signature` example);
//! only CAs a root signed are kept.
//!
//! ```console
//! curl -sO https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml
//! cargo run -p ti-pki --example tsl -- ECC-RSA_TSL.xml
//! cargo run -p ti-pki --features dangerous-nonprod --example tsl -- --env ref ECC-RSA_TSL-ref.xml
//! ```

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::tsl::{self, Tsl};
use ti_pki::{Env, Timestamp, TrustConfig, roots};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut env = Env::Prod;
    if args.first().map(String::as_str) == Some("--env") && args.len() > 1 {
        env = args[1].parse()?;
        args.drain(..2);
    }
    let [path] = args.as_slice() else {
        eprintln!("usage: tsl [--env <env>] <tsl.xml>");
        std::process::exit(2);
    };
    let now = Timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());

    #[cfg(feature = "dangerous-nonprod")]
    let config = TrustConfig::preset(env);
    #[cfg(not(feature = "dangerous-nonprod"))]
    let config = if env.is_prod() {
        TrustConfig::preset_prod()
    } else {
        return Err(format!("{env} needs --features dangerous-nonprod").into());
    };

    let list = Tsl::parse(&std::fs::read(path)?)?;
    println!("sequence      {}", list.sequence_number);
    println!("issued        {}", list.issued_at);
    match list.next_update {
        Some(next) if next < now => println!("next update   {next} (OVERDUE)"),
        Some(next) => println!("next update   {next}"),
        None => println!("next update   none (closed list)"),
    }
    let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
    for service in &list.services {
        *by_type.entry(service.service_type.as_str()).or_default() += 1;
    }
    println!("services      {}", list.services.len());
    for (service_type, count) in by_type {
        println!("  {count:>4}        {service_type}");
    }

    let store = roots::load(&config, now)?.store();
    let candidates = list.intermediate_cas();
    let matched = tsl::match_to_roots(candidates.iter().cloned(), &store, &config.algorithms);
    println!(
        "roots         {} ({env}, walked from {})",
        store.len(),
        store.roots().first().map_or("-", |r| r.subject_cn())
    );
    println!(
        "CAs           {} listed, {} kept, {} rejected",
        candidates.len(),
        matched.intermediates.len(),
        matched.rejected.len()
    );
    let mut per_root: BTreeMap<&str, usize> = BTreeMap::new();
    for ca in matched.intermediates.iter().map(|i| &i.certificate) {
        *per_root.entry(ca.issuer_cn()).or_default() += 1;
    }
    for (root, count) in per_root {
        println!("  {count:>4}        under {root}");
    }
    for (ca, reason) in matched.rejected.iter().map(|(i, r)| (&i.certificate, r)) {
        let expired = if ca.is_valid_at(now) { "" } else { ", expired" };
        println!(
            "  rejected    {} (issuer {}{expired}): {reason}",
            ca.subject_cn(),
            ca.issuer_cn()
        );
    }
    let expired = matched
        .intermediates
        .iter()
        .filter(|ca| !ca.certificate.is_valid_at(now))
        .count();
    if expired > 0 {
        println!("  note        {expired} kept CAs are expired; path validation rejects them");
    }
    Ok(())
}
