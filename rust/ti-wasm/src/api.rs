/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The exports as plain Rust, errors as strings: what the `#[wasm_bindgen]` wrappers
//! call, and what native tests run.
#![forbid(unsafe_code)]

use std::time::Duration;

use serde::Serialize;
use ti_pki::config::MAX_TSL_GRACE_PERIOD;
use ti_pki::{Certificate, Env, Timestamp, TrustConfig, parse_pem_certificates};
use ti_report::{CertificateInfo, CheckContext, SCHEMA, describe, tsl_view};

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
    let config = config_for(env, grace_seconds)?;
    Ok(to_json(&tsl_view(xml, env, &config, roots_json, now)))
}

/// See [`crate::describe_certificate`].
///
/// # Errors
///
/// A bad time, or no certificate in `input`.
pub fn describe_certificate(input: &[u8], now: &str) -> Result<String, String> {
    let now = parse_now(now)?;
    let certificates = parse_certificates(input)?;
    Ok(to_json(&Certificates {
        schema: SCHEMA,
        certificates: certificates.iter().map(|c| describe(c, now)).collect(),
    }))
}

/// See [`crate::TrustContext`].
pub struct Context(CheckContext);

impl Context {
    /// See [`crate::TrustContext::new`].
    ///
    /// # Errors
    ///
    /// An unknown environment, a bad time or a grace period over 30 days.
    pub fn new(
        xml: &[u8],
        env: &str,
        now: &str,
        roots_json: Option<&[u8]>,
        grace_seconds: u32,
    ) -> Result<Self, String> {
        let env = parse_env(env)?;
        let now = parse_now(now)?;
        let config = config_for(env, grace_seconds)?;
        Ok(Context(CheckContext::new(
            env, config, roots_json, xml, now,
        )))
    }

    /// See [`crate::TrustContext::tsl`].
    pub fn tsl(&self) -> String {
        to_json(self.0.tsl())
    }

    /// See [`crate::TrustContext::check`].
    ///
    /// # Errors
    ///
    /// A bad time, or no certificate in `input`.
    pub fn check(&self, input: &[u8], now: &str) -> Result<String, String> {
        let now = parse_now(now)?;
        let certificates = parse_certificates(input)?;
        Ok(to_json(&self.0.check(&certificates, now)))
    }
}

fn config_for(env: Env, grace_seconds: u32) -> Result<TrustConfig, String> {
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
    Ok(config)
}

/// PEM (any number of certificates, the end entity first) or one DER certificate.
fn parse_certificates(input: &[u8]) -> Result<Vec<Certificate>, String> {
    let certificates = if input.trim_ascii_start().starts_with(b"-----") {
        parse_pem_certificates(input).map_err(|e| format!("PEM: {e}"))?
    } else {
        vec![Certificate::from_der(input).map_err(|e| format!("DER: {e}"))?]
    };
    if certificates.is_empty() {
        return Err("no certificate in the input".to_owned());
    }
    Ok(certificates)
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
