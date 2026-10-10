//! Strict JSON for JOSE objects: a JSON text whose top level is an object, read into a
//! [`serde_json::Map`] while refusing duplicate member names at every depth.
//!
//! RFC 7515 §5.2 step 4 and RFC 7516 §5.2 step 4 let a parser either reject duplicate
//! header parameter names or keep the last one; serde_json keeps the last one. Two
//! parsers that disagree on which duplicate wins disagree on what a token says, so jwz
//! rejects duplicates everywhere: headers, JWKs, JWK Sets, claims.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::error::{Error, ErrorCode};

/// The members of the JSON object in `text`; `context` names it in errors.
///
/// # Errors
///
/// [`ErrorCode::DuplicateMember`] for a repeated member name at any depth,
/// [`ErrorCode::Json`] for anything that is not one JSON object.
pub fn parse_object(text: &[u8], context: &'static str) -> Result<Map<String, Value>, Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(text);
    let value = StrictValue
        .deserialize(&mut deserializer)
        .map_err(|e| classify(&e, context))?;
    deserializer
        .end()
        .map_err(|_| Error::new(ErrorCode::Json, context))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(Error::new(ErrorCode::Json, context)),
    }
}

/// The marker a duplicate leaves in the serde error, to tell it from other errors
/// without exposing the member name.
const DUPLICATE: &str = "jwz: duplicate member";

fn classify(e: &serde_json::Error, context: &'static str) -> Error {
    if format!("{e}").starts_with(DUPLICATE) {
        Error::new(ErrorCode::DuplicateMember, context)
    } else {
        Error::new(ErrorCode::Json, context)
    }
}

/// Deserializes any JSON value like `serde_json::Value`, refusing duplicate members.
struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(String::from(v)))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValue)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let value = map.next_value_seed(StrictValue)?;
            // RFC 7515 §5.2 step 4: reject, never keep the last.
            if members.insert(name, value).is_some() {
                return Err(de::Error::custom(DUPLICATE));
            }
        }
        Ok(Value::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7515_5_2_step_4_duplicate_members_are_refused_at_every_depth() {
        for text in [
            r#"{"alg":"ES256","alg":"none"}"#,
            r#"{"jwk":{"kty":"EC","kty":"oct"}}"#,
            r#"{"keys":[{"kid":"a","kid":"b"}]}"#,
        ] {
            assert_eq!(
                parse_object(text.as_bytes(), "t").map_err(|e| e.code()),
                Err(ErrorCode::DuplicateMember),
                "{text}"
            );
        }
    }

    #[test]
    fn only_a_single_object_is_accepted() {
        let map = parse_object(br#"{"a":1,"b":[true,null,"x"],"c":{"d":1.5}}"#, "t").unwrap();
        assert_eq!(map.len(), 3);
        for text in ["[1]", "\"x\"", "{} {}", "{\"a\":1", ""] {
            assert_eq!(
                parse_object(text.as_bytes(), "t").map_err(|e| e.code()),
                Err(ErrorCode::Json),
                "{text}"
            );
        }
    }

    #[test]
    fn the_error_never_carries_the_member_name() {
        let e = parse_object(br#"{"secret-name":1,"secret-name":2}"#, "jwk").unwrap_err();
        assert!(!format!("{e}").contains("secret-name"));
    }
}
