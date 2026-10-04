//! The exports as plain Rust, errors as strings: what the `#[wasm_bindgen]` wrappers
//! call, and what native tests run.
#![forbid(unsafe_code)]

use std::time::Duration;

use serde::Serialize;
use ti_pki::config::MAX_TSL_GRACE_PERIOD;
use ti_pki::{Certificate, Env, Timestamp, TrustConfig, parse_pem_certificates};
use ti_report::{CertificateInfo, SCHEMA, describe, tsl_view};

#[derive(Serialize)]
struct Version {
    ti_wasm: &'static str,
    schema: u32,
}

#[derive(Serialize)]
struct TrustUrls {
    environment: &'static str,
    tsl_url: String,
    roots_url: String,
}

#[derive(Serialize)]
struct Certificates {
    schema: u32,
    certificates: Vec<CertificateInfo>,
}

/// See [`crate::version`].
pub fn version() -> String {
    to_json(&Version {
        ti_wasm: env!("CARGO_PKG_VERSION"),
        schema: SCHEMA,
    })
}

/// See [`crate::trust_urls`].
///
/// # Errors
///
/// An unknown environment.
pub fn trust_urls(env: &str) -> Result<String, String> {
    let env = parse_env(env)?;
    let config = TrustConfig::preset(env);
    Ok(to_json(&TrustUrls {
        environment: env.as_str(),
        tsl_url: config.tsl_url.into_owned(),
        roots_url: config.roots_url.into_owned(),
    }))
}

/// See [`crate::verify_tsl`].
///
/// # Errors
///
/// An unknown environment, a bad time or a grace period over 30 days.
pub fn verify_tsl(
    xml: &[u8],
    env: &str,
    now: &str,
    roots_json: Option<&[u8]>,
    grace_seconds: u32,
) -> Result<String, String> {
    let env = parse_env(env)?;
    let now = parse_now(now)?;
    let grace = Duration::from_secs(u64::from(grace_seconds));
    if grace > MAX_TSL_GRACE_PERIOD {
        return Err(format!(
            "grace period {grace_seconds} s exceeds {} s",
            MAX_TSL_GRACE_PERIOD.as_secs()
        ));
    }
    let config = TrustConfig {
        tsl_grace_period: grace,
        ..TrustConfig::preset(env)
    };
    config
        .validate(env.tier())
        .map_err(|e| format!("configuration for {env}: {e}"))?;
    Ok(to_json(&tsl_view(xml, env, &config, roots_json, now)))
}

/// See [`crate::describe_certificate`].
///
/// # Errors
///
/// A bad time, or no certificate in `input`.
pub fn describe_certificate(input: &[u8], now: &str) -> Result<String, String> {
    let now = parse_now(now)?;
    let certificates = if input.trim_ascii_start().starts_with(b"-----") {
        parse_pem_certificates(input).map_err(|e| format!("PEM: {e}"))?
    } else {
        vec![Certificate::from_der(input).map_err(|e| format!("DER: {e}"))?]
    };
    if certificates.is_empty() {
        return Err("no certificate in the input".to_owned());
    }
    Ok(to_json(&Certificates {
        schema: SCHEMA,
        certificates: certificates.iter().map(|c| describe(c, now)).collect(),
    }))
}

fn parse_env(env: &str) -> Result<Env, String> {
    env.parse()
        .map_err(|_| format!("unknown environment {env:?}; expected prod, ref, test or dev"))
}

fn parse_now(now: &str) -> Result<Timestamp, String> {
    Timestamp::parse_rfc3339(now).ok_or_else(|| format!("not an RFC 3339 time: {now:?}"))
}

fn to_json(value: &impl Serialize) -> String {
    serde_json::to_string(value).expect("reports serialize: string keys, no failing Serialize")
}
