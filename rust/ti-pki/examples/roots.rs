//! Runs the A_28419 cross-certificate walk and prints which roots end up trusted and
//! where the walk stopped.
//!
//! ```console
//! cargo run -p ti-pki --example roots                          # embedded prod roots.json
//! cargo run -p ti-pki --example roots -- prod roots.json       # a downloaded one
//! cargo run -p ti-pki --features dangerous-nonprod --example roots -- test
//! ```

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::key::classify_key;
use ti_pki::{Env, Timestamp, TrustConfig, roots};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let env: Env = args.next().as_deref().unwrap_or("prod").parse()?;
    #[cfg(feature = "dangerous-nonprod")]
    let mut config = TrustConfig::preset(env);
    #[cfg(not(feature = "dangerous-nonprod"))]
    let mut config = if env.is_prod() {
        TrustConfig::preset_prod()
    } else {
        return Err(format!("{env} needs --features dangerous-nonprod").into());
    };
    if let Some(path) = args.next() {
        config.roots = Cow::Owned(std::fs::read(&path)?);
        println!("roots.json    {path}");
    } else {
        println!("roots.json    embedded ({env})");
    }
    let now = Timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    let anchor = ti_pki::Certificate::from_der(&config.anchor)?;
    println!("anchor        {}", anchor.subject_cn());
    println!("at            {now}");
    println!();

    let walk = roots::load(&config, now)?;
    println!("trusted roots ({}):", walk.trusted.len());
    for root in &walk.trusted {
        let (_, key) = classify_key(root.public_key_info(), now);
        println!(
            "  {:<22} {:<22} {} .. {}",
            root.subject_cn(),
            key,
            root.not_before(),
            root.not_after()
        );
    }
    println!();
    println!(
        "forward walk  {}",
        walk.forward_stop.as_deref().unwrap_or("complete")
    );
    println!(
        "backward walk {}",
        walk.backward_stop.as_deref().unwrap_or("complete")
    );
    Ok(())
}
