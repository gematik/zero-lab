//! The JWE JSON serializations (RFC 7516 §7.2): general (several recipients) and
//! flattened (one).
//!
//! jwz is stricter than RFC 7516 in one way: `enc`, `crit` and `zip` must be in the
//! protected header, so the content cipher and the critical extensions are covered by
//! the tag. `alg` may be per recipient, as several recipients need different ones; a
//! changed `alg` yields a different CEK, and the tag fails.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use serde_json::{Map, Value};

use super::{
    Encrypted, EncryptionKey, Jwe, UNSUPPORTED, encode_header, entries, key_id, manage, party_from,
    random,
};
use crate::b64;
use crate::crypto::Backend;
use crate::error::{Error, ErrorCode};
use crate::header::{Header, HeaderParams};
use crate::json;
use crate::jwa::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm, Registry};
use crate::profile::Policy;

/// Every recipient of a JWE in JSON serialization, each accepted under `policy`.
///
/// # Errors
///
/// [`ErrorCode::TokenTooLarge`], [`ErrorCode::Malformed`] for a structure that is
/// neither serialization or headers that are not disjoint, and the errors of
/// [`Jwe::parse`] for each recipient.
pub fn parse(
    text: &str,
    policy: &Policy,
    registry: &Registry,
) -> Result<Vec<Jwe<Encrypted>>, Error> {
    if text.len() > policy.max_token_len {
        return Err(Error::new(ErrorCode::TokenTooLarge, "jwe json"));
    }
    let malformed = Error::new(ErrorCode::Malformed, "jwe json");
    let object = json::parse_object(text.as_bytes(), "jwe json")?;
    let string = |name: &str| object.get(name).and_then(Value::as_str).ok_or(malformed);
    let protected = string("protected")?;
    let protected_header = Header::decode(protected)?;
    // RFC 7516 §5.1 step 14: ASCII(protected), and '.' and the encoded aad if present.
    let mut aad = protected.as_bytes().to_vec();
    if let Some(extra) = object.get("aad") {
        let extra = extra.as_str().ok_or(malformed)?;
        b64::decode(extra, "aad")?;
        aad.push(b'.');
        aad.extend_from_slice(extra.as_bytes());
    }
    let (iv, ciphertext, tag) = (string("iv")?, string("ciphertext")?, string("tag")?);

    let mut shared = protected_header.members().clone();
    if let Some(unprotected) = object.get("unprotected") {
        merge(&mut shared, unprotected)?;
    }
    // RFC 7516 §7.2.1 (general) has "recipients"; §7.2.2 (flattened) has the members
    // of one recipient at the top level. Both at once is neither.
    let recipients: Vec<&Map<String, Value>> = match object.get("recipients") {
        Some(Value::Array(items))
            if !object.contains_key("header")
                && !object.contains_key("encrypted_key")
                && !items.is_empty() =>
        {
            items
                .iter()
                .map(|item| item.as_object().ok_or(malformed))
                .collect::<Result<_, _>>()?
        }
        None => vec![&object],
        Some(_) => return Err(malformed),
    };
    recipients
        .into_iter()
        .map(|recipient| {
            let mut merged = shared.clone();
            if let Some(header) = recipient.get("header") {
                merge(&mut merged, header)?;
            }
            let encrypted_key = match recipient.get("encrypted_key") {
                None => "",
                Some(value) => value.as_str().ok_or(malformed)?,
            };
            Jwe::accept(
                Header::from_members(merged),
                aad.clone(),
                [encrypted_key, iv, ciphertext, tag],
                policy,
                registry,
            )
        })
        .collect()
}

/// RFC 7516 §7.2.1: the protected, shared unprotected and per-recipient headers MUST be
/// disjoint. jwz: `enc`, `crit` and `zip` only count when protected.
fn merge(into: &mut Map<String, Value>, unprotected: &Value) -> Result<(), Error> {
    let malformed = Error::new(ErrorCode::Malformed, "jwe json header");
    for (name, value) in unprotected.as_object().ok_or(malformed)? {
        if into.contains_key(name) || matches!(name.as_str(), "enc" | "crit" | "zip") {
            return Err(malformed);
        }
        into.insert(name.clone(), value.clone());
    }
    Ok(())
}

/// One recipient of [`encrypt`].
#[derive(Clone, Debug)]
pub struct Recipient<'a> {
    /// Its key management algorithm.
    pub alg: KeyEncryptionAlgorithm,
    /// Its key.
    pub key: EncryptionKey<'a>,
    /// Its unprotected header parameters (`kid` defaults to the key's).
    pub header: HeaderParams,
}

/// Encrypts `plaintext` once for all `recipients` into the general JSON serialization
/// (RFC 7516 §7.2.1): `enc` and `protected` in the protected header, `alg`, `kid` and
/// `epk` per recipient, `aad` authenticated but not encrypted.
///
/// # Errors
///
/// [`ErrorCode::InvalidMember`] without recipients, for a direct mode (`dir`, `ECDH-ES`)
/// among several recipients, or for a parameter both in the protected and a recipient's
/// header; otherwise as [`super::encrypt`].
pub fn encrypt(
    plaintext: &[u8],
    enc: ContentEncryptionAlgorithm,
    protected: HeaderParams,
    recipients: &[Recipient<'_>],
    aad: Option<&[u8]>,
    registry: &Registry,
    backend: &dyn Backend,
) -> Result<String, Error> {
    let protected = protected.into_members(&[("enc", enc.as_str())]);
    let first = recipients
        .first()
        .ok_or(Error::new(ErrorCode::InvalidMember, "no recipients"))?;
    let (_, cee) = entries(first.alg, enc, registry)?;
    // One recipient may use a direct mode, which determines the CEK itself.
    let shared_cek = if recipients.len() > 1 {
        Some(random(backend, cee.key_len)?)
    } else {
        None
    };

    let mut cek = None;
    let mut entries_out = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let (kek, cee) = entries(recipient.alg, enc, registry)?;
        let kid = key_id(recipient.key).filter(|_| !recipient.header.has("kid"));
        let mut set = vec![("alg", recipient.alg.as_str())];
        if let Some(kid) = kid {
            set.push(("kid", kid));
        }
        let mut header = recipient.header.clone().into_members(&set);
        if header.keys().any(|name| protected.contains_key(name)) {
            return Err(Error::new(ErrorCode::InvalidMember, "header not disjoint"));
        }
        let mut visible = protected.clone();
        visible.extend(header.clone());
        let (apu, apv) = party_from(&visible)?;
        let managed = manage(
            &kek,
            &cee,
            recipient.key,
            shared_cek.as_deref().map(Vec::as_slice),
            (&apu, &apv),
            registry,
            backend,
        )?;
        for (name, value) in managed.members {
            header.insert(name.into(), value);
        }
        let mut entry = Map::new();
        entry.insert("header".into(), Value::Object(header));
        // RFC 7516 §7.2.1: encrypted_key is absent when empty.
        if !managed.encrypted_key.is_empty() {
            entry.insert(
                "encrypted_key".into(),
                Value::String(b64::encode(&managed.encrypted_key)),
            );
        }
        entries_out.push(Value::Object(entry));
        cek.get_or_insert(managed.cek);
    }
    let cek = cek.ok_or(Error::new(ErrorCode::InvalidMember, "no recipients"))?;

    let encoded_protected = encode_header(&protected)?;
    let mut authenticated = encoded_protected.clone().into_bytes();
    let encoded_aad = aad.map(b64::encode);
    if let Some(extra) = &encoded_aad {
        authenticated.push(b'.');
        authenticated.extend_from_slice(extra.as_bytes());
    }
    let iv = random(backend, cee.iv_len)?;
    let cipher = backend.aead(enc).ok_or(UNSUPPORTED)?;
    let sealed = cipher.seal(&cek, &iv, &authenticated, plaintext)?;

    let mut object = Map::new();
    object.insert("protected".into(), Value::String(encoded_protected));
    object.insert("recipients".into(), Value::Array(entries_out));
    if let Some(extra) = encoded_aad {
        object.insert("aad".into(), Value::String(extra));
    }
    object.insert("iv".into(), Value::String(b64::encode(&iv)));
    object.insert(
        "ciphertext".into(),
        Value::String(b64::encode(&sealed.ciphertext)),
    );
    object.insert("tag".into(), Value::String(b64::encode(&sealed.tag)));
    serde_json::to_string(&Value::Object(object))
        .map_err(|_| Error::new(ErrorCode::Json, "jwe json"))
}
