//! Validation profiles: a [`Profile`] is a named, versioned bundle of a [`Policy`] (what
//! a token may use), [`KeyConstraints`] (what keys may be used) and a [`ClaimsPolicy`]
//! (what a JWT must claim).
//!
//! [`Policy::check_jws`] and [`Policy::check_jwe`] are the one place where a header is
//! accepted: its algorithms, its `crit` list, its key-reference parameters and its
//! `typ`. Parsing calls them before any cryptography runs; nothing else in jwz decides
//! whether an algorithm is acceptable.
//!
//! Profiles are data and compose: [`Profile::with`] widens one profile by another (the
//! union of what either allows), so a token accepted under a profile is accepted under
//! every composition containing it. Restricting is done by writing a narrower profile.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorCode};
use crate::header::{Header, REGISTERED};
use crate::jwa::{
    ContentEncryptionAlgorithm, ContentEncryptionEntry, ContentEncryptionKind, Curve,
    KeyEncryptionAlgorithm, KeyEncryptionEntry, KeyManagementMode, KeyType, Registry,
    SignatureAlgorithm, Support,
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
    /// Curves the `epk` of an ECDH-ES JWE may be on.
    pub key_agreement_curves: Vec<Curve>,
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

    /// Accepts the JWE header `header` and returns its key management and content
    /// encryption algorithms.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::MissingMember`] without `alg` or `enc`;
    /// [`ErrorCode::UnsupportedAlgorithm`] for an algorithm `registry` does not know as
    /// available, a key management mode or content cipher jwz does not implement
    /// (RSA, PBES2, CBC-HMAC); [`ErrorCode::PolicyViolation`] for one the policy does
    /// not allow, `zip`, and the checks [`check_jws`](Self::check_jws) shares;
    /// [`ErrorCode::Critical`] for a `crit` it cannot honour.
    pub fn check_jwe(
        &self,
        header: &Header,
        registry: &Registry,
    ) -> Result<(KeyEncryptionEntry, ContentEncryptionEntry), Error> {
        // RFC 7516 §4.1.1, §4.1.2: alg and enc are required.
        let alg = header
            .alg()
            .ok_or(Error::new(ErrorCode::MissingMember, "alg"))?;
        let enc = header
            .enc()
            .ok_or(Error::new(ErrorCode::MissingMember, "enc"))?;
        let kek = registry
            .key_encryption(alg)
            .filter(|e| e.support == Support::Available)
            .filter(|e| {
                matches!(
                    e.mode,
                    KeyManagementMode::DirectEncryption
                        | KeyManagementMode::DirectKeyAgreement
                        | KeyManagementMode::KeyWrapping { .. }
                        | KeyManagementMode::KeyAgreementWithKeyWrapping { .. }
                )
            })
            .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "alg"))?;
        let cee = registry
            .content_encryption(enc)
            .filter(|e| e.support == Support::Available && e.kind == ContentEncryptionKind::Aead)
            .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "enc"))?;
        if !self.key_encryption_algorithms.contains(&kek.alg) {
            return Err(Error::new(ErrorCode::PolicyViolation, "alg not allowed"));
        }
        if !self.content_encryption_algorithms.contains(&cee.enc) {
            return Err(Error::new(ErrorCode::PolicyViolation, "enc not allowed"));
        }
        if let Some(curve) = epk_curve(header, registry)
            && !self.key_agreement_curves.contains(&curve)
        {
            return Err(Error::new(
                ErrorCode::PolicyViolation,
                "epk curve not allowed",
            ));
        }
        // RFC 7516 §4.1.3: compression before encryption leaks the plaintext's
        // redundancy and makes decryption a decompression bomb; jwz does not implement it.
        if header.get("zip").is_some() {
            return Err(Error::new(ErrorCode::PolicyViolation, "zip unsupported"));
        }
        self.check_common(header)?;
        Ok((*kek, *cee))
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
        union_into(&mut self.key_agreement_curves, &other.key_agreement_curves);
        union_into(&mut self.understood_critical, &other.understood_critical);
        self.max_token_len = self.max_token_len.max(other.max_token_len);
        self.key_references = self.key_references.union(other.key_references);
        if self.typ != other.typ {
            self.typ = None;
        }
        self
    }
}

/// The registered curve `epk` names, if any; whether `epk` is otherwise well-formed is
/// JWE's structural check, not policy.
fn epk_curve(header: &Header, registry: &Registry) -> Option<Curve> {
    let crv = header.get("epk")?.get("crv")?.as_str()?;
    registry.curve(crv).map(|e| e.crv)
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

/// What a JWT's claims must satisfy (RFC 7519 §4.1); checked by
/// [`jwt::Claims::validate`](crate::jwt) once the token is verified or decrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimsPolicy {
    /// The `iss` required, if any.
    pub issuer: Option<String>,
    /// A value `aud` must contain, if any.
    pub audience: Option<String>,
    /// Clock skew tolerated for `exp`, `nbf` and `iat`, in seconds.
    pub leeway: u64,
    /// Whether `exp` must be present.
    pub require_exp: bool,
    /// The oldest `iat` accepted, in seconds before now; `iat` is required when set.
    pub max_age: Option<u64>,
    /// Further claims that must be present.
    pub required: Vec<String>,
}

impl ClaimsPolicy {
    /// The union: either policy's tokens pass. Issuer and audience stay only where both
    /// require the same, the larger leeway and age, `exp` required only if both require
    /// it, the claims both require.
    #[must_use]
    pub fn with(mut self, other: &ClaimsPolicy) -> ClaimsPolicy {
        if self.issuer != other.issuer {
            self.issuer = None;
        }
        if self.audience != other.audience {
            self.audience = None;
        }
        self.leeway = self.leeway.max(other.leeway);
        self.require_exp = self.require_exp && other.require_exp;
        self.max_age = match (self.max_age, other.max_age) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        self.required.retain(|name| other.required.contains(name));
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
    /// What a JWT must claim.
    pub claims: ClaimsPolicy,
}

/// Profile names reserved for profiles not defined yet; asking for one by name fails
/// instead of silently giving a different profile.
pub const RESERVED: &[&str] = &["oauth-dpop", "openid-federation", "eudi-wallet"];

impl Profile {
    /// The default: modern public-key algorithms only (ES256, EdDSA; ECDH-ES on P-256,
    /// AES-GCM), no key references in tokens, no extensions, 256 KiB at most; a JWT
    /// must have `exp`, with 60 seconds of clock skew.
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
                key_agreement_curves: alloc::vec![Curve::P256],
                max_token_len: DEFAULT_MAX_TOKEN_LEN,
                understood_critical: Vec::new(),
                key_references: KeyReferences::default(),
                typ: None,
            },
            keys: KeyConstraints {
                curves: alloc::vec![Curve::P256, Curve::ED25519],
                require_kid: false,
            },
            claims: ClaimsPolicy {
                issuer: None,
                audience: None,
                leeway: 60,
                require_exp: true,
                max_age: None,
                required: Vec::new(),
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
                key_agreement_curves: registry
                    .curves()
                    .iter()
                    .filter(|e| available(e.support) && e.key_type == KeyType::EC)
                    .map(|e| e.crv)
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
            claims: ClaimsPolicy {
                issuer: None,
                audience: None,
                leeway: 60,
                require_exp: false,
                max_age: None,
                required: Vec::new(),
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
            claims: self.claims.with(&other.claims),
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
    fn rfc_7516_jwe_header_acceptance() {
        let registry = Registry::standard();
        let policy = Profile::strict().policy;
        let check = |h: serde_json::Value| {
            policy
                .check_jwe(&header(h), &registry)
                .map(|(kek, cee)| (kek.alg, cee.enc))
                .map_err(|e| e.code())
        };
        assert_eq!(
            check(json!({"alg": "ECDH-ES", "enc": "A256GCM"})),
            Ok((
                KeyEncryptionAlgorithm::ECDH_ES,
                ContentEncryptionAlgorithm::A256GCM
            ))
        );
        for (h, code) in [
            (json!({"enc": "A256GCM"}), ErrorCode::MissingMember),
            (json!({"alg": "ECDH-ES"}), ErrorCode::MissingMember),
            (
                json!({"alg": "RSA1_5", "enc": "A256GCM"}),
                ErrorCode::UnsupportedAlgorithm,
            ),
            (
                json!({"alg": "PBES2-HS256+A128KW", "enc": "A256GCM"}),
                ErrorCode::UnsupportedAlgorithm,
            ),
            (
                json!({"alg": "ECDH-ES", "enc": "A128CBC-HS256"}),
                ErrorCode::UnsupportedAlgorithm,
            ),
            (
                json!({"alg": "dir", "enc": "A256GCM"}),
                ErrorCode::PolicyViolation,
            ),
            (
                json!({"alg": "ECDH-ES", "enc": "A192GCM"}),
                ErrorCode::PolicyViolation,
            ),
            (
                json!({"alg": "ECDH-ES", "enc": "A256GCM", "zip": "DEF"}),
                ErrorCode::PolicyViolation,
            ),
            (
                json!({"alg": "ECDH-ES", "enc": "A256GCM", "crit": ["x"], "x": 1}),
                ErrorCode::Critical,
            ),
            (
                json!({"alg": "ECDH-ES", "enc": "A256GCM", "jku": "https://x"}),
                ErrorCode::PolicyViolation,
            ),
        ] {
            assert_eq!(check(h.clone()), Err(code), "{h}");
        }
    }

    #[test]
    fn claims_policy_union() {
        let a = Profile::strict().claims;
        let b = ClaimsPolicy {
            issuer: Some("https://idp".into()),
            audience: None,
            leeway: 5,
            require_exp: false,
            max_age: Some(300),
            required: alloc::vec!["sub".into()],
        };
        let union = a.clone().with(&b);
        assert_eq!(union.issuer, None);
        assert_eq!(union.leeway, 60);
        assert!(!union.require_exp);
        assert_eq!(union.max_age, None);
        assert!(union.required.is_empty());
        assert_eq!(b.clone().with(&b), b);
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
