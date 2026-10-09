//! Validation profiles: a [`Profile`] is a named, versioned bundle of a [`Policy`] (what
//! a token may use) and [`KeyConstraints`] (what keys may be used); claims constraints
//! join in stage S4.
//!
//! [`Policy::check_jws`] is the one place where a JWS header is accepted: its algorithm,
//! its `crit` list, its key-reference parameters and its `typ`. JWS parsing calls it
//! before any cryptography runs; nothing else in jwz decides whether an algorithm is
//! acceptable.
//!
//! Profiles are data and compose: [`Profile::with`] widens one profile by another (the
//! union of what either allows), so a token accepted under a profile is accepted under
//! every composition containing it. Restricting is done by writing a narrower profile.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorCode};
use crate::header::{Header, REGISTERED};
use crate::jwa::{
    ContentEncryptionAlgorithm, Curve, KeyEncryptionAlgorithm, Registry, SignatureAlgorithm,
    Support,
};

/// Header parameters that point at or carry a key; each must be opted into, because a
/// token that brings its own key proves nothing unless that key is validated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one opt-in per header parameter"
)]
pub struct KeyReferences {
    /// `jwk`: a key embedded in the header.
    pub jwk: bool,
    /// `jku`: a URL of a JWK Set.
    pub jku: bool,
    /// `x5u`: a URL of a certificate chain.
    pub x5u: bool,
    /// `x5c`: an embedded certificate chain.
    pub x5c: bool,
}

impl KeyReferences {
    /// Every key reference allowed.
    pub const ALL: KeyReferences = KeyReferences {
        jwk: true,
        jku: true,
        x5u: true,
        x5c: true,
    };

    fn union(self, other: KeyReferences) -> KeyReferences {
        KeyReferences {
            jwk: self.jwk || other.jwk,
            jku: self.jku || other.jku,
            x5u: self.x5u || other.x5u,
            x5c: self.x5c || other.x5c,
        }
    }
}

/// What a token may use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// JWS `alg` values accepted.
    pub signature_algorithms: Vec<SignatureAlgorithm>,
    /// JWE `alg` values accepted.
    pub key_encryption_algorithms: Vec<KeyEncryptionAlgorithm>,
    /// JWE `enc` values accepted.
    pub content_encryption_algorithms: Vec<ContentEncryptionAlgorithm>,
    /// Largest token accepted, in bytes; checked before anything is decoded.
    pub max_token_len: usize,
    /// Extension parameters this application understands and so may appear in `crit`.
    pub understood_critical: Vec<String>,
    /// Which key-reference header parameters may appear.
    pub key_references: KeyReferences,
    /// The `typ` a token must have, if any (compared as RFC 7515 §4.1.9 says).
    pub typ: Option<String>,
}

/// Default maximum token size: large enough for a JWT with an `x5c` chain, small enough
/// that parsing an attacker's token stays cheap.
pub const DEFAULT_MAX_TOKEN_LEN: usize = 256 * 1024;

impl Policy {
    /// Accepts the JWS header `header` and returns its algorithm.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::MissingMember`] without `alg`; [`ErrorCode::UnsupportedAlgorithm`] for
    /// an algorithm `registry` does not know as available (`none` never is);
    /// [`ErrorCode::PolicyViolation`] for one the policy does not allow, a key reference
    /// it does not opt into, the wrong `typ` or the unsupported `b64`;
    /// [`ErrorCode::Critical`] for a `crit` it cannot honour.
    pub fn check_jws(
        &self,
        header: &Header,
        registry: &Registry,
    ) -> Result<SignatureAlgorithm, Error> {
        // RFC 7515 §4.1.1: alg is required; RFC 7518 §3.6: `none` is never registered.
        let name = header
            .alg()
            .ok_or(Error::new(ErrorCode::MissingMember, "alg"))?;
        let entry = registry
            .signature(name)
            .filter(|e| e.support == Support::Available)
            .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "alg"))?;
        if !self.signature_algorithms.contains(&entry.alg) {
            return Err(Error::new(ErrorCode::PolicyViolation, "alg not allowed"));
        }
        self.check_common(header)?;
        Ok(entry.alg)
    }

    /// The checks every JOSE header gets, whatever its algorithm family.
    fn check_common(&self, header: &Header) -> Result<(), Error> {
        self.check_critical(header)?;
        self.check_key_references(header)?;
        // RFC 7797 (`b64`) changes the signing input; jwz does not implement it.
        if header.get("b64").is_some() {
            return Err(Error::new(ErrorCode::PolicyViolation, "b64 unsupported"));
        }
        if let Some(expected) = &self.typ
            && !header
                .typ()
                .is_some_and(|typ| same_media_type(typ, expected))
        {
            return Err(Error::new(ErrorCode::PolicyViolation, "typ"));
        }
        Ok(())
    }

    /// RFC 7515 §4.1.11: `crit` is a non-empty array of distinct names, each an
    /// extension (not a registered parameter), each present in the header, each
    /// understood by the recipient.
    fn check_critical(&self, header: &Header) -> Result<(), Error> {
        let Some(crit) = header.get("crit") else {
            return Ok(());
        };
        let malformed = Error::new(ErrorCode::Critical, "crit");
        let names = crit.as_array().ok_or(malformed)?;
        if names.is_empty() {
            return Err(malformed);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(names.len());
        for name in names {
            let name = name.as_str().ok_or(malformed)?;
            if seen.contains(&name) || REGISTERED.contains(&name) || header.get(name).is_none() {
                return Err(malformed);
            }
            if !self.understood_critical.iter().any(|u| u == name) {
                return Err(Error::new(
                    ErrorCode::Critical,
                    "crit names a parameter not understood",
                ));
            }
            seen.push(name);
        }
        Ok(())
    }

    fn check_key_references(&self, header: &Header) -> Result<(), Error> {
        let allowed = self.key_references;
        for (name, opted_in) in [
            ("jwk", allowed.jwk),
            ("jku", allowed.jku),
            ("x5u", allowed.x5u),
            ("x5c", allowed.x5c),
        ] {
            if !opted_in && header.get(name).is_some() {
                return Err(Error::new(
                    ErrorCode::PolicyViolation,
                    "key reference not allowed",
                ));
            }
        }
        Ok(())
    }

    /// The union of both policies: every algorithm and extension either allows, the
    /// larger size limit, every key reference either opts into, and `typ` only where
    /// both require the same one.
    #[must_use]
    pub fn with(mut self, other: &Policy) -> Policy {
        union_into(&mut self.signature_algorithms, &other.signature_algorithms);
        union_into(
            &mut self.key_encryption_algorithms,
            &other.key_encryption_algorithms,
        );
        union_into(
            &mut self.content_encryption_algorithms,
            &other.content_encryption_algorithms,
        );
        union_into(&mut self.understood_critical, &other.understood_critical);
        self.max_token_len = self.max_token_len.max(other.max_token_len);
        self.key_references = self.key_references.union(other.key_references);
        if self.typ != other.typ {
            self.typ = None;
        }
        self
    }
}

/// RFC 7515 §4.1.9: media types are compared case-insensitively, and `application/` may
/// be omitted when there is no other `/`.
fn same_media_type(a: &str, b: &str) -> bool {
    fn normal(t: &str) -> &str {
        let lower_prefix = t
            .get(..12)
            .is_some_and(|p| p.eq_ignore_ascii_case("application/"));
        if lower_prefix {
            t.get(12..).unwrap_or(t)
        } else {
            t
        }
    }
    normal(a).eq_ignore_ascii_case(normal(b))
}

fn union_into<T: Clone + PartialEq>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

/// What keys may be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyConstraints {
    /// Curves keys may be on (`crv` of EC and OKP keys, `epk` of ECDH-ES).
    pub curves: Vec<Curve>,
    /// Whether a token must name its key with `kid`.
    pub require_kid: bool,
}

impl KeyConstraints {
    fn with(mut self, other: &KeyConstraints) -> KeyConstraints {
        union_into(&mut self.curves, &other.curves);
        self.require_kid = self.require_kid && other.require_kid;
        self
    }
}

/// A named, versioned validation profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The name, e.g. `strict`.
    pub name: String,
    /// Bumped whenever the profile accepts or refuses something new.
    pub version: u32,
    /// What a token may use.
    pub policy: Policy,
    /// What keys may be used.
    pub keys: KeyConstraints,
}

/// Profile names reserved for profiles not defined yet; asking for one by name fails
/// instead of silently giving a different profile.
pub const RESERVED: &[&str] = &["oauth-dpop", "openid-federation", "eudi-wallet"];

impl Profile {
    /// The default: modern public-key algorithms only (ES256, EdDSA; ECDH-ES on P-256,
    /// AES-GCM), no key references in tokens, no extensions, 256 KiB at most.
    pub fn strict() -> Profile {
        Profile {
            name: "strict".into(),
            version: 1,
            policy: Policy {
                signature_algorithms: alloc::vec![
                    SignatureAlgorithm::ES256,
                    SignatureAlgorithm::EDDSA,
                ],
                key_encryption_algorithms: alloc::vec![
                    KeyEncryptionAlgorithm::ECDH_ES,
                    KeyEncryptionAlgorithm::ECDH_ES_A128KW,
                    KeyEncryptionAlgorithm::ECDH_ES_A256KW,
                ],
                content_encryption_algorithms: alloc::vec![
                    ContentEncryptionAlgorithm::A128GCM,
                    ContentEncryptionAlgorithm::A256GCM,
                ],
                max_token_len: DEFAULT_MAX_TOKEN_LEN,
                understood_critical: Vec::new(),
                key_references: KeyReferences::default(),
                typ: None,
            },
            keys: KeyConstraints {
                curves: alloc::vec![Curve::P256, Curve::ED25519],
                require_kid: false,
            },
        }
    }

    /// Permissive, for interoperability tests: every algorithm `registry` knows as
    /// available, every key reference, 1 MiB. Never for production verification.
    pub fn rfc7518_interop(registry: &Registry) -> Profile {
        let available = |s: Support| s == Support::Available;
        Profile {
            name: "rfc7518-interop".into(),
            version: 1,
            policy: Policy {
                signature_algorithms: registry
                    .signatures()
                    .iter()
                    .filter(|e| available(e.support))
                    .map(|e| e.alg)
                    .collect(),
                key_encryption_algorithms: registry
                    .key_encryptions()
                    .iter()
                    .filter(|e| available(e.support))
                    .map(|e| e.alg)
                    .collect(),
                content_encryption_algorithms: registry
                    .content_encryptions()
                    .iter()
                    .filter(|e| available(e.support))
                    .map(|e| e.enc)
                    .collect(),
                max_token_len: 1024 * 1024,
                understood_critical: Vec::new(),
                key_references: KeyReferences::ALL,
                typ: None,
            },
            keys: KeyConstraints {
                curves: registry
                    .curves()
                    .iter()
                    .filter(|e| available(e.support))
                    .map(|e| e.crv)
                    .collect(),
                require_kid: false,
            },
        }
    }

    /// The shipped profile called `name`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnsupportedAlgorithm`] for a [`RESERVED`] or unknown name.
    pub fn by_name(name: &str, registry: &Registry) -> Result<Profile, Error> {
        match name {
            "strict" => Ok(Profile::strict()),
            "rfc7518-interop" => Ok(Profile::rfc7518_interop(registry)),
            _ => Err(Error::new(
                ErrorCode::UnsupportedAlgorithm,
                "profile not available",
            )),
        }
    }

    /// This profile widened by `other` ([`Policy::with`]); the name records both.
    #[must_use]
    pub fn with(self, other: &Profile) -> Profile {
        Profile {
            name: alloc::format!("{}+{}", self.name, other.name),
            version: self.version.max(other.version),
            policy: self.policy.with(&other.policy),
            keys: self.keys.with(&other.keys),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use serde_json::json;

    fn header(value: serde_json::Value) -> Header {
        let serde_json::Value::Object(members) = value else {
            panic!("a header is an object");
        };
        Header::from_members(members)
    }

    #[test]
    fn rfc_7518_3_6_none_is_refused_in_every_casing() {
        let registry = Registry::standard();
        let policy = Profile::rfc7518_interop(&registry).policy;
        for alg in ["none", "None", "NONE", "nOnE"] {
            assert_eq!(
                policy
                    .check_jws(&header(json!({"alg": alg})), &registry)
                    .map_err(|e| e.code()),
                Err(ErrorCode::UnsupportedAlgorithm),
                "{alg}"
            );
        }
    }

    #[test]
    fn strict_accepts_es256_and_refuses_the_rest() {
        let registry = Registry::standard();
        let policy = Profile::strict().policy;
        assert_eq!(
            policy.check_jws(&header(json!({"alg": "ES256"})), &registry),
            Ok(SignatureAlgorithm::ES256)
        );
        for (alg, code) in [
            // Known and available only with the `hmac` feature; refused either way.
            (
                "HS256",
                if cfg!(feature = "hmac") {
                    ErrorCode::PolicyViolation
                } else {
                    ErrorCode::UnsupportedAlgorithm
                },
            ),
            ("PS256", ErrorCode::UnsupportedAlgorithm),
            ("BP256R1", ErrorCode::UnsupportedAlgorithm),
            ("es256", ErrorCode::UnsupportedAlgorithm),
        ] {
            let result = policy.check_jws(&header(json!({"alg": alg})), &registry);
            assert_eq!(result.map_err(|e| e.code()), Err(code), "{alg}");
        }
        assert_eq!(
            policy
                .check_jws(&header(json!({"kid": "1"})), &registry)
                .map_err(|e| e.code()),
            Err(ErrorCode::MissingMember)
        );
    }

    #[test]
    fn rfc_7515_4_1_11_crit() {
        let registry = Registry::standard();
        let mut policy = Profile::strict().policy;
        policy.understood_critical.push("exp".to_string());
        let check = |h: serde_json::Value| {
            policy
                .check_jws(&header(h), &registry)
                .map_err(|e| e.code())
        };
        assert!(check(json!({"alg": "ES256", "crit": ["exp"], "exp": 1})).is_ok());
        for bad in [
            json!({"alg": "ES256", "crit": ["other"], "other": 1}),
            json!({"alg": "ES256", "crit": ["exp"]}),
            json!({"alg": "ES256", "crit": [], "exp": 1}),
            json!({"alg": "ES256", "crit": ["alg"]}),
            json!({"alg": "ES256", "crit": ["exp", "exp"], "exp": 1}),
            json!({"alg": "ES256", "crit": "exp", "exp": 1}),
        ] {
            assert_eq!(check(bad.clone()), Err(ErrorCode::Critical), "{bad}");
        }
    }

    #[test]
    fn key_references_need_an_opt_in() {
        let registry = Registry::standard();
        let strict = Profile::strict().policy;
        let interop = Profile::rfc7518_interop(&registry).policy;
        for name in ["jwk", "jku", "x5u", "x5c"] {
            let h = header(json!({"alg": "ES256", name: "x"}));
            assert_eq!(
                strict.check_jws(&h, &registry).map_err(|e| e.code()),
                Err(ErrorCode::PolicyViolation),
                "{name}"
            );
            assert!(interop.check_jws(&h, &registry).is_ok(), "{name}");
        }
    }

    #[test]
    fn rfc_7515_4_1_9_typ_comparison() {
        let registry = Registry::standard();
        let mut policy = Profile::strict().policy;
        policy.typ = Some("dpop+jwt".into());
        for (typ, ok) in [
            ("dpop+jwt", true),
            ("DPoP+JWT", true),
            ("application/dpop+jwt", true),
            ("JWT", false),
        ] {
            let h = header(json!({"alg": "ES256", "typ": typ}));
            assert_eq!(policy.check_jws(&h, &registry).is_ok(), ok, "{typ}");
        }
        assert!(
            policy
                .check_jws(&header(json!({"alg": "ES256"})), &registry)
                .is_err()
        );
    }

    #[test]
    fn composition_only_widens() {
        let registry = Registry::standard();
        let strict = Profile::strict();
        let composed = strict.clone().with(&Profile::rfc7518_interop(&registry));
        assert!(composed.name.contains("strict"));
        for alg in &strict.policy.signature_algorithms {
            assert!(composed.policy.signature_algorithms.contains(alg));
        }
        assert!(composed.policy.max_token_len >= strict.policy.max_token_len);
        assert_eq!(
            Profile::by_name("oauth-dpop", &registry).map_err(|e| e.code()),
            Err(ErrorCode::UnsupportedAlgorithm)
        );
    }
}
