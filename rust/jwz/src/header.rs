//! JOSE headers: the parsed [`Header`] of a JWS or JWE, read with typed accessors, and
//! [`HeaderParams`] for building one. A header is only ever accepted through
//! [`Policy`](crate::profile::Policy); this module reads, it does not judge.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use serde_json::{Map, Value};

use crate::b64;
use crate::error::{Error, ErrorCode};
use crate::json;
use crate::jwk::Jwk;

/// Header parameter names RFC 7515 §4.1, RFC 7516 §4.1 and RFC 7518 §4.6.1 / §4.7.1 /
/// §4.8.1 define. `crit` may not name them (RFC 7515 §4.1.11).
pub const REGISTERED: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc",
    "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// A decoded JOSE header: the members of its JSON object, duplicates refused.
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    members: Map<String, Value>,
}

impl Header {
    /// The header encoded in the base64url `encoded`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Base64`], [`ErrorCode::DuplicateMember`] or [`ErrorCode::Json`].
    pub fn decode(encoded: &str) -> Result<Header, Error> {
        let bytes = b64::decode(encoded, "header")?;
        Ok(Header {
            members: json::parse_object(&bytes, "header")?,
        })
    }

    /// A header from members already parsed (the unprotected part of a JSON
    /// serialization).
    #[cfg(any(feature = "jws", test))]
    pub(crate) fn from_members(members: Map<String, Value>) -> Header {
        Header { members }
    }

    /// Every member.
    pub fn members(&self) -> &Map<String, Value> {
        &self.members
    }

    /// The member `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members.get(name)
    }

    /// A string member; `None` if absent or not a string.
    pub fn str(&self, name: &str) -> Option<&str> {
        self.members.get(name).and_then(Value::as_str)
    }

    /// `alg`.
    pub fn alg(&self) -> Option<&str> {
        self.str("alg")
    }

    /// `kid`.
    pub fn kid(&self) -> Option<&str> {
        self.str("kid")
    }

    /// `typ`.
    pub fn typ(&self) -> Option<&str> {
        self.str("typ")
    }

    /// `cty`.
    pub fn cty(&self) -> Option<&str> {
        self.str("cty")
    }

    /// `x5t#S256`.
    pub fn x5t_s256(&self) -> Option<&str> {
        self.str("x5t#S256")
    }

    /// `x5c` as DER certificates, leaf first. RFC 7515 §4.1.6: standard base64 (not
    /// base64url) with padding.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMember`] if it is not an array of strings,
    /// [`ErrorCode::Base64`] for an entry that is not canonical base64.
    pub fn x5c(&self) -> Result<Option<Vec<Vec<u8>>>, Error> {
        let Some(value) = self.members.get("x5c") else {
            return Ok(None);
        };
        let invalid = Error::new(ErrorCode::InvalidMember, "x5c");
        let entries = value.as_array().ok_or(invalid)?;
        if entries.is_empty() {
            return Err(invalid);
        }
        let mut chain = Vec::with_capacity(entries.len());
        for entry in entries {
            let text = entry.as_str().ok_or(invalid)?;
            let der = Base64::decode_vec(text).map_err(|_| Error::new(ErrorCode::Base64, "x5c"))?;
            chain.push(der);
        }
        Ok(Some(chain))
    }

    /// `jwk`, the key embedded in the header.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMember`] if it is not an object, or the errors of
    /// [`Jwk::parse`].
    pub fn jwk(&self) -> Result<Option<Jwk>, Error> {
        match self.members.get("jwk") {
            None => Ok(None),
            Some(value @ Value::Object(_)) => Jwk::parse(&value.to_string()).map(Some),
            Some(_) => Err(Error::new(ErrorCode::InvalidMember, "jwk")),
        }
    }
}

/// The header parameters a producer sets; `alg` (and `enc` for JWE) come from the key
/// and algorithm, never from here.
#[derive(Clone, Debug, Default)]
pub struct HeaderParams {
    members: Map<String, Value>,
    critical: Vec<String>,
}

impl HeaderParams {
    /// No parameters.
    pub fn new() -> Self {
        HeaderParams::default()
    }

    /// `typ`, e.g. `JWT` or `dpop+jwt`.
    #[must_use]
    pub fn typ(self, typ: &str) -> Self {
        self.string("typ", typ)
    }

    /// `cty`.
    #[must_use]
    pub fn cty(self, cty: &str) -> Self {
        self.string("cty", cty)
    }

    /// `kid`; without it, the signer's key ID is used.
    #[must_use]
    pub fn kid(self, kid: &str) -> Self {
        self.string("kid", kid)
    }

    /// `x5c` from DER certificates, leaf first.
    #[must_use]
    pub fn x5c(mut self, chain: &[&[u8]]) -> Self {
        let entries = chain
            .iter()
            .map(|der| Value::String(Base64::encode_string(der)))
            .collect();
        self.members.insert("x5c".into(), Value::Array(entries));
        self
    }

    /// `jwk`, the public key, embedded.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::KeyMismatch`] if `jwk` holds private material.
    pub fn jwk(mut self, jwk: &Jwk) -> Result<Self, Error> {
        if jwk.is_private() {
            return Err(Error::new(
                ErrorCode::KeyMismatch,
                "header jwk must be public",
            ));
        }
        let value = json::parse_object(jwk.to_json().as_bytes(), "jwk")?;
        self.members.insert("jwk".into(), Value::Object(value));
        Ok(self)
    }

    /// Any other parameter.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMember`] for `alg`, `enc` or `crit`, which jwz sets itself.
    pub fn param(mut self, name: &str, value: Value) -> Result<Self, Error> {
        if matches!(name, "alg" | "enc" | "crit") {
            return Err(Error::new(
                ErrorCode::InvalidMember,
                "header parameter set by jwz",
            ));
        }
        self.members.insert(name.to_string(), value);
        Ok(self)
    }

    /// An extension parameter that recipients must understand: it is added and listed
    /// in `crit` (RFC 7515 §4.1.11).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Critical`] for a name RFC 7515/7516/7518 defines.
    pub fn critical(mut self, name: &str, value: Value) -> Result<Self, Error> {
        if REGISTERED.contains(&name) {
            return Err(Error::new(
                ErrorCode::Critical,
                "crit names a registered parameter",
            ));
        }
        self.members.insert(name.to_string(), value);
        self.critical.push(name.to_string());
        Ok(self)
    }

    fn string(mut self, name: &str, value: &str) -> Self {
        self.members
            .insert(name.to_string(), Value::String(value.to_string()));
        self
    }

    /// Whether `name` is set.
    pub fn has(&self, name: &str) -> bool {
        self.members.contains_key(name)
    }

    /// The header object with `alg` (and further members jwz sets) added.
    #[cfg(feature = "jws")]
    pub(crate) fn into_members(mut self, set: &[(&str, &str)]) -> Map<String, Value> {
        for (name, value) in set {
            self.members
                .insert((*name).to_string(), Value::String((*value).to_string()));
        }
        if !self.critical.is_empty() {
            let names = self.critical.into_iter().map(Value::String).collect();
            self.members.insert("crit".into(), Value::Array(names));
        }
        self.members
    }
}
