//! The JWS JSON serializations (RFC 7515 §7.2): general (several signatures) and
//! flattened (one).
//!
//! jwz is stricter than RFC 7515 here in two ways: `alg` and `crit` must be in the
//! protected header (RFC 7515 §4.1.11 already demands that of `crit`), so a policy never
//! accepts an algorithm an attacker could change; and a signature entry without a
//! protected header is refused.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};

use super::{Jws, Unverified, protected_header, signing_input};
use crate::b64;
use crate::error::{Error, ErrorCode};
use crate::header::{Header, HeaderParams};
use crate::json;
use crate::jwa::Registry;
use crate::keys::{Signature, Signer};
use crate::profile::Policy;

/// Every signature of a JWS in JSON serialization, each accepted under `policy`.
///
/// # Errors
///
/// [`ErrorCode::TokenTooLarge`], [`ErrorCode::Malformed`] for a structure that is
/// neither serialization or headers that are not disjoint, and the errors of
/// [`Jws::parse`] for each signature.
pub fn parse(
    text: &str,
    policy: &Policy,
    registry: &Registry,
) -> Result<Vec<Jws<Unverified>>, Error> {
    if text.len() > policy.max_token_len {
        return Err(Error::new(ErrorCode::TokenTooLarge, "jws json"));
    }
    let malformed = Error::new(ErrorCode::Malformed, "jws json");
    let object = json::parse_object(text.as_bytes(), "jws json")?;
    let encoded_payload = object
        .get("payload")
        .and_then(Value::as_str)
        .ok_or(malformed)?;
    let payload = b64::decode(encoded_payload, "payload")?;
    // RFC 7515 §7.2.1 (general) has "signatures"; §7.2.2 (flattened) has the members of
    // one signature at the top level. Both at once is neither.
    let entries: Vec<&Map<String, Value>> = match object.get("signatures") {
        Some(Value::Array(items)) if !object.contains_key("signature") && !items.is_empty() => {
            items
                .iter()
                .map(|item| item.as_object().ok_or(malformed))
                .collect::<Result<_, _>>()?
        }
        None => alloc::vec![&object],
        Some(_) => return Err(malformed),
    };
    entries
        .into_iter()
        .map(|entry| one_signature(entry, encoded_payload, &payload, policy, registry))
        .collect()
}

fn one_signature(
    entry: &Map<String, Value>,
    encoded_payload: &str,
    payload: &[u8],
    policy: &Policy,
    registry: &Registry,
) -> Result<Jws<Unverified>, Error> {
    let malformed = Error::new(ErrorCode::Malformed, "jws json signature");
    let protected = entry
        .get("protected")
        .and_then(Value::as_str)
        .ok_or(malformed)?;
    let protected_header = Header::decode(protected)?;
    let mut merged = protected_header.members().clone();
    if let Some(unprotected) = entry.get("header") {
        let unprotected = unprotected.as_object().ok_or(malformed)?;
        for (name, value) in unprotected {
            // RFC 7515 §7.2.1: the protected and unprotected headers MUST be disjoint.
            // jwz: alg and crit only count when protected.
            if merged.contains_key(name) || matches!(name.as_str(), "alg" | "crit") {
                return Err(malformed);
            }
            merged.insert(name.clone(), value.clone());
        }
    }
    let header = Header::from_members(merged);
    let alg = policy.check_jws(&header, registry)?;
    let signature = entry
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(malformed)?;
    Ok(Jws::from_parts(
        header,
        alg,
        protected.to_string(),
        encoded_payload.to_string(),
        payload.to_vec(),
        Signature::from(b64::decode(signature, "signature")?),
    ))
}

/// Signs `payload` once per signer into the general JSON serialization (RFC 7515
/// §7.2.1); each signer's header parameters are protected.
///
/// # Errors
///
/// A signer's error.
pub fn sign(payload: &[u8], signers: &[(&dyn Signer, HeaderParams)]) -> Result<String, Error> {
    let encoded_payload = b64::encode(payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for (signer, params) in signers {
        let protected = protected_header(params.clone(), *signer)?;
        let input = signing_input(&protected, &encoded_payload);
        let signature = signer.try_sign(input.as_bytes())?;
        let mut entry = Map::new();
        entry.insert("protected".into(), Value::String(protected));
        entry.insert(
            "signature".into(),
            Value::String(b64::encode(signature.as_bytes())),
        );
        signatures.push(Value::Object(entry));
    }
    let mut object = Map::new();
    object.insert("payload".into(), Value::String(encoded_payload));
    object.insert("signatures".into(), Value::Array(signatures));
    Ok(Value::Object(object).to_string())
}
