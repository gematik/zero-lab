//! The TI's TSL verification and certificate reports for JavaScript, as `ti-report`
//! builds them: every function is pure, the caller passes the bytes and the instant and
//! gets JSON back. Network and clock stay in JavaScript, so the same module runs on a
//! server and in a browser.
//!
//! A `JsError` means the caller asked wrongly (unknown environment, bad time, grace
//! period too long, no certificate); every verification verdict is inside the JSON.

pub mod api;

use wasm_bindgen::prelude::wasm_bindgen;

/// `{"ti_wasm","schema"}`.
#[wasm_bindgen]
pub fn version() -> String {
    api::version()
}

/// `{"environment","tsl_url","roots_url"}` for `env` (`prod`, `ref`, `test`, `dev`).
///
/// # Errors
///
/// An unknown environment.
#[wasm_bindgen]
pub fn trust_urls(env: &str) -> Result<String, wasm_bindgen::JsError> {
    api::trust_urls(env).map_err(|e| wasm_bindgen::JsError::new(&e))
}

/// The TSL view (`schemas/tsl-view.json`) of `xml` verified for `env` at `now` (RFC
/// 3339), with `roots_json` as fresher roots if given and `grace_seconds` past
/// `NextUpdate` tolerated.
///
/// # Errors
///
/// An unknown environment, a bad time or a grace period over 30 days.
#[wasm_bindgen]
#[allow(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen takes an optional byte array only as an owned Vec"
)]
pub fn verify_tsl(
    xml: &[u8],
    env: &str,
    now: &str,
    roots_json: Option<Vec<u8>>,
    grace_seconds: u32,
) -> Result<String, wasm_bindgen::JsError> {
    api::verify_tsl(xml, env, now, roots_json.as_deref(), grace_seconds)
        .map_err(|e| wasm_bindgen::JsError::new(&e))
}

/// `{"schema","certificates":[…]}`: every certificate in `input` (DER or PEM) as `ti pki
/// inspect` describes it at `now` (RFC 3339).
///
/// # Errors
///
/// A bad time, or no certificate in `input`.
#[wasm_bindgen]
pub fn describe_certificate(input: &[u8], now: &str) -> Result<String, wasm_bindgen::JsError> {
    api::describe_certificate(input, now).map_err(|e| wasm_bindgen::JsError::new(&e))
}
