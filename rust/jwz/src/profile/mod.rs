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

//! Validation profiles: a [`Profile`] is a named, versioned bundle of a [`Policy`] (what
//! a token may use) and a [`ClaimsPolicy`] (what a JWT must claim).
//!
//! [`Policy::check_jws`] and [`Policy::check_jwe`] are the one place where a header is
//! accepted: its algorithms, its `crit` list, its key-reference parameters, its `kid`
//! and its `typ`. Parsing calls them before any cryptography runs; nothing else in jwz decides
//! whether an algorithm is acceptable. The same policy binds what jwz produces:
//! [`Policy::check_signing_key`] and [`Policy::check_encryption`] are where signing and
//! encryption are accepted, so jwz never produces a token its own profile refuses.
//!
//! A profile is the explicit lists its construction results in. [`Profile::new`] starts
//! with none; [`Profile::with`] appends the lists of an [`Algorithms`] bundle, and the
//! constants of this module ([`ECDSA_NIST`], [`EDDSA`], [`ECDH_ES_P256`], ...) are the
//! bundles jwz offers; an extension crate offers its own beside them. What a profile
//! accepts is read off its construction:
//!
//! ```
//! use jwz::jwa::{Curve, SignatureAlgorithm};
//! use jwz::profile::{AES_256_GCM, ECDH_ES_DIRECT_P256, ECDSA_NIST, Profile};
//!
//! let mine = Profile::new("mine", 1)
//!     .with(&ECDSA_NIST)
//!     .with(&ECDH_ES_DIRECT_P256)
//!     .with(&AES_256_GCM);
//! assert_eq!(mine.policy.signature_algorithms, [SignatureAlgorithm::ES256]);
//! assert_eq!(mine.policy.signing_curves, [Curve::P256]);
//! ```
//!
//! Composition only appends, so a token accepted under a profile is accepted under every
//! profile built from it. A narrower profile is another construction, not a removal.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorCode};
use crate::header::{Header, REGISTERED};
use crate::jwa::{
    ContentEncryptionAlgorithm, ContentEncryptionEntry, ContentEncryptionKind, Curve,
    KeyEncryptionAlgorithm, KeyEncryptionEntry, KeyManagementMode, KeyType, Registry,
    SignatureAlgorithm, SignatureEntry, Support,
};

/// Header parameters that point at or carry a key; each must be opted into, because a
/// token that brings its own key proves nothing unless that key is validated.
///
/// RFC 8725 §3.10: a followed `jku` or `x5u` invites server-side request forgery; jwz
/// never fetches either, and a host that does holds the URL to its own allowlist.
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
}

/// What a token may use, and what jwz may produce under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// JWS `alg` values accepted.
    pub signature_algorithms: Vec<SignatureAlgorithm>,
    /// Curves a signing key may be on, for the algorithms whose key type has curves
    /// (`EC`, `OKP`).
    pub signing_curves: Vec<Curve>,
    /// JWE `alg` values accepted.
    pub key_encryption_algorithms: Vec<KeyEncryptionAlgorithm>,
    /// JWE `enc` values accepted.
    pub content_encryption_algorithms: Vec<ContentEncryptionAlgorithm>,
    /// Curves an ECDH-ES key may be on: the `epk` of a JWE received, the recipient's key
    /// of a JWE produced.
    pub key_agreement_curves: Vec<Curve>,
    /// Largest token accepted, in bytes; checked before anything is decoded.
    pub max_token_len: usize,
    /// Extension parameters this application understands and so may appear in `crit`.
    pub understood_critical: Vec<String>,
    /// Which key-reference header parameters may appear.
    pub key_references: KeyReferences,
    /// Whether a token must name its key with a non-empty `kid`.
    pub require_kid: bool,
    /// The `typ` a token must have, if any (compared as RFC 7515 §4.1.9 says): the
    /// explicit type that tells one kind of JWT from another (RFC 8725 §3.11).
    pub typ: Option<String>,
}

/// Default maximum token size: large enough for a JWT with an `x5c` chain, small enough
/// that parsing an attacker's token stays cheap.
pub const DEFAULT_MAX_TOKEN_LEN: usize = 256 * 1024;

/// What a JWS key must be for one accepted algorithm under a policy, recorded when the
/// header is accepted so that verification needs neither the policy nor the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningKeyRule {
    /// Whether the algorithm's key type has curves (`EC`, `OKP`). HMAC's `oct` keys have
    /// none and are bound by their algorithm alone.
    curved: bool,
    /// The algorithm's registered curve: the curve of a key that states none.
    registered: Option<Curve>,
    /// The policy's signing curves.
    allowed: Vec<Curve>,
}

impl SigningKeyRule {
    /// Accepts a key that states `curve` (or none).
    pub(crate) fn check(&self, curve: Option<Curve>) -> Result<(), Error> {
        if !self.curved {
            return Ok(());
        }
        match curve.or(self.registered) {
            Some(curve) if self.allowed.contains(&curve) => Ok(()),
            Some(_) => Err(Error::new(
                ErrorCode::PolicyViolation,
                "key curve not allowed",
            )),
            // EdDSA's curve is the key's (RFC 8037 §3.1): a key that does not say which
            // could be on any, and the curve is what the profile decides on.
            None => Err(Error::new(
                ErrorCode::PolicyViolation,
                "key states no curve",
            )),
        }
    }
}

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
        self.accept_jws(header, registry).map(|(alg, _)| alg)
    }

    /// [`check_jws`](Self::check_jws), and the rule the verifying key must meet.
    pub(crate) fn accept_jws(
        &self,
        header: &Header,
        registry: &Registry,
    ) -> Result<(SignatureAlgorithm, SigningKeyRule), Error> {
        // RFC 7515 §4.1.1: alg is required; RFC 7518 §3.6: `none` is never registered.
        let name = header
            .alg()
            .ok_or(Error::new(ErrorCode::MissingMember, "alg"))?;
        let entry = self.allowed_signature(name, registry)?;
        self.check_common(header)?;
        Ok((entry.alg, self.signing_key_rule(entry)))
    }

    /// Accepts signing with a key for `alg` that states `curve` (or none): what
    /// `jws::sign` checks before it signs, and verification before it verifies.
    ///
    /// RFC 8725 §3.1: the profile, not the key, decides which algorithms are used. A key's
    /// curve is the one it states ([`JwsKey::curve`](crate::keys::JwsKey::curve)) or
    /// else the algorithm's registered one (P-256 for ES256, RFC 7518 §3.4); for an
    /// algorithm whose key type has curves (`EC`, `OKP`) it must be one of the policy's
    /// `signing_curves`. HMAC keys have no curve and are bound by their algorithm alone.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnsupportedAlgorithm`] for an algorithm `registry` does not know as
    /// available; [`ErrorCode::PolicyViolation`] for one the policy does not allow, a
    /// curve it does not list, or no curve where the algorithm needs one.
    pub fn check_signing_key(
        &self,
        alg: SignatureAlgorithm,
        curve: Option<Curve>,
        registry: &Registry,
    ) -> Result<(), Error> {
        let entry = self.allowed_signature(alg.as_str(), registry)?;
        self.signing_key_rule(entry).check(curve)
    }

    /// The registry's entry for `name`, if it is available and the policy allows it.
    fn allowed_signature<'r>(
        &self,
        name: &str,
        registry: &'r Registry,
    ) -> Result<&'r SignatureEntry, Error> {
        // RFC 8725 §3.1: an allowlist matched by exact name, never a blocklist, so a name
        // in another casing or spelling is no algorithm at all.
        let entry = registry
            .signature(name)
            .filter(|e| e.support == Support::Available)
            .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "alg"))?;
        if !self.signature_algorithms.contains(&entry.alg) {
            return Err(Error::new(ErrorCode::PolicyViolation, "alg not allowed"));
        }
        Ok(entry)
    }

    fn signing_key_rule(&self, entry: &SignatureEntry) -> SigningKeyRule {
        SigningKeyRule {
            curved: entry.key_type == KeyType::EC || entry.key_type == KeyType::OKP,
            registered: entry.curve,
            allowed: self.signing_curves.clone(),
        }
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
    /// not allow, an `epk` on a curve it does not list, `zip`, and the checks
    /// [`check_jws`](Self::check_jws) shares; [`ErrorCode::Critical`] for a `crit` it
    /// cannot honour.
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
        self.check_encryption(kek.alg, cee.enc, epk_curve(header, registry))?;
        // RFC 7516 §4.1.3, RFC 8725 §3.6: compression before encryption leaks the
        // plaintext's redundancy and makes decryption a decompression bomb; jwz does not
        // implement it.
        if header.get("zip").is_some() {
            return Err(Error::new(ErrorCode::PolicyViolation, "zip unsupported"));
        }
        self.check_common(header)?;
        Ok((*kek, *cee))
    }

    /// Accepts JWE key management `alg` and content encryption `enc` with an ECDH-ES key
    /// on `agreement_curve`, where there is one: the `epk` of a JWE received
    /// ([`check_jwe`](Self::check_jwe)), the recipient's key of a JWE produced
    /// (`jwe::encrypt`, which checks before it encrypts).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::PolicyViolation`] for an algorithm or curve the policy does not list.
    pub fn check_encryption(
        &self,
        alg: KeyEncryptionAlgorithm,
        enc: ContentEncryptionAlgorithm,
        agreement_curve: Option<Curve>,
    ) -> Result<(), Error> {
        if !self.key_encryption_algorithms.contains(&alg) {
            return Err(Error::new(ErrorCode::PolicyViolation, "alg not allowed"));
        }
        if !self.content_encryption_algorithms.contains(&enc) {
            return Err(Error::new(ErrorCode::PolicyViolation, "enc not allowed"));
        }
        if let Some(curve) = agreement_curve
            && !self.key_agreement_curves.contains(&curve)
        {
            return Err(Error::new(
                ErrorCode::PolicyViolation,
                "key agreement curve not allowed",
            ));
        }
        Ok(())
    }

    /// The checks every JOSE header gets, whatever its algorithm family.
    fn check_common(&self, header: &Header) -> Result<(), Error> {
        self.check_critical(header)?;
        self.check_key_references(header)?;
        if self.require_kid && header.kid().is_none_or(str::is_empty) {
            return Err(Error::new(ErrorCode::PolicyViolation, "kid required"));
        }
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
        const MALFORMED: Error = Error::new(ErrorCode::Critical, "crit");
        let Some(crit) = header.get("crit") else {
            return Ok(());
        };
        let names = crit.as_array().ok_or(MALFORMED)?;
        if names.is_empty() {
            return Err(MALFORMED);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(names.len());
        for name in names {
            let name = name.as_str().ok_or(MALFORMED)?;
            if seen.contains(&name) || REGISTERED.contains(&name) || header.get(name).is_none() {
                return Err(MALFORMED);
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
}

/// The registered curve `epk` names, if any; whether `epk` is otherwise well-formed is
/// JWE's structural check, not policy.
fn epk_curve(header: &Header, registry: &Registry) -> Option<Curve> {
    let crv = header.get("epk")?.get("crv")?.as_str()?;
    registry.curve(crv).map(|e| e.crv)
}

/// RFC 7515 §4.1.9: media types are compared case-insensitively, and `application/` may
/// be omitted when there is no other `/`.
pub(crate) fn same_media_type(a: &str, b: &str) -> bool {
    fn normal(t: &str) -> &str {
        let lower_prefix = t
            .get(..12)
            .is_some_and(|p| p.eq_ignore_ascii_case("application/"));
        // Only the short form of a media type has no other `/`: `application/a/b` is not
        // the long form of `a/b`, and stays as it is.
        match t.get(12..) {
            Some(rest) if lower_prefix && !rest.contains('/') => rest,
            _ => t,
        }
    }
    normal(a).eq_ignore_ascii_case(normal(b))
}

pub(crate) fn union_into<T: Clone + PartialEq>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

/// What a JWT's claims must satisfy (RFC 7519 §4.1); checked by
/// [`jwt::Claims::validate`](crate::jwt) once the token is verified or decrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimsPolicy {
    /// The `iss` required, if any: the issuer whose keys verified the token
    /// (RFC 8725 §3.8).
    pub issuer: Option<String>,
    /// A value `aud` must contain, if any; a token without `aud` is then refused
    /// (RFC 8725 §3.9).
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

/// A bundle of algorithm lists a profile is extended by ([`Profile::with`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithms<'a> {
    /// JWS `alg` values.
    pub signatures: &'a [SignatureAlgorithm],
    /// Curves a signing key may be on ([`Policy::signing_curves`]).
    pub signing_curves: &'a [Curve],
    /// JWE `alg` values.
    pub key_encryption: &'a [KeyEncryptionAlgorithm],
    /// JWE `enc` values.
    pub content_encryption: &'a [ContentEncryptionAlgorithm],
    /// Curves an ECDH-ES key may be on ([`Policy::key_agreement_curves`]).
    pub key_agreement_curves: &'a [Curve],
}

impl Algorithms<'_> {
    /// No algorithm and no curve: [`Profile::with`] it changes nothing, and the other
    /// constants are written as what they add to it.
    pub const NONE: Algorithms<'static> = Algorithms {
        signatures: &[],
        signing_curves: &[],
        key_encryption: &[],
        content_encryption: &[],
        key_agreement_curves: &[],
    };
}

/// ECDSA on the NIST curves (RFC 7518 §3.4): `ES256` with keys on P-256. `ES384` on
/// P-384 and `ES512` on P-521 are registered but reserved, not available, in jwz 0.2;
/// they join this bundle when they are implemented.
pub const ECDSA_NIST: Algorithms<'static> = Algorithms {
    signatures: &[SignatureAlgorithm::ES256],
    signing_curves: &[Curve::P256],
    ..Algorithms::NONE
};

/// `Ed25519` (RFC 9864 §2.2): EdDSA whose algorithm names its curve, as every other
/// signature algorithm does.
pub const ED25519: Algorithms<'static> = Algorithms {
    signatures: &[SignatureAlgorithm::ED25519],
    signing_curves: &[Curve::ED25519],
    ..Algorithms::NONE
};

/// The polymorphic `EdDSA` (RFC 8037 §3.1) with keys on Ed25519, the one curve jwz
/// implements; the key, not the algorithm, names the curve. Deprecated by RFC 9864
/// §4.1.2: for peers that still send it, never in [`Profile::strict`].
pub const EDDSA: Algorithms<'static> = Algorithms {
    signatures: &[SignatureAlgorithm::EDDSA],
    signing_curves: &[Curve::ED25519],
    ..Algorithms::NONE
};

/// HMAC with SHA-2 (RFC 7518 §3.2): `HS256`, `HS384`, `HS512`. Shared keys have no
/// curve. They are available only with the `hmac` feature; without it the registry
/// reports them as unsupported whatever a profile lists.
pub const HMAC: Algorithms<'static> = Algorithms {
    signatures: &[
        SignatureAlgorithm::HS256,
        SignatureAlgorithm::HS384,
        SignatureAlgorithm::HS512,
    ],
    ..Algorithms::NONE
};

/// ECDH-ES on P-256 (RFC 7518 §4.6): direct key agreement and with AES Key Wrap of 128
/// and 256 bits (`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW`).
pub const ECDH_ES_P256: Algorithms<'static> = Algorithms {
    key_encryption: &[
        KeyEncryptionAlgorithm::ECDH_ES,
        KeyEncryptionAlgorithm::ECDH_ES_A128KW,
        KeyEncryptionAlgorithm::ECDH_ES_A256KW,
    ],
    key_agreement_curves: &[Curve::P256],
    ..Algorithms::NONE
};

/// ECDH-ES on P-256 as direct key agreement only (RFC 7518 §4.6.2: the agreed key is
/// the CEK), without key wrapping.
pub const ECDH_ES_DIRECT_P256: Algorithms<'static> = Algorithms {
    key_encryption: &[KeyEncryptionAlgorithm::ECDH_ES],
    key_agreement_curves: &[Curve::P256],
    ..Algorithms::NONE
};

/// AES Key Wrap with a shared key (RFC 7518 §4.4): `A128KW`, `A192KW`, `A256KW`.
pub const AES_KW: Algorithms<'static> = Algorithms {
    key_encryption: &[
        KeyEncryptionAlgorithm::A128KW,
        KeyEncryptionAlgorithm::A192KW,
        KeyEncryptionAlgorithm::A256KW,
    ],
    ..Algorithms::NONE
};

/// Direct encryption with a shared key (RFC 7518 §4.5): `dir`.
pub const DIRECT: Algorithms<'static> = Algorithms {
    key_encryption: &[KeyEncryptionAlgorithm::DIR],
    ..Algorithms::NONE
};

/// AES-GCM content encryption (RFC 7518 §5.3): `A128GCM`, `A192GCM`, `A256GCM`.
pub const AES_GCM: Algorithms<'static> = Algorithms {
    content_encryption: &[
        ContentEncryptionAlgorithm::A128GCM,
        ContentEncryptionAlgorithm::A192GCM,
        ContentEncryptionAlgorithm::A256GCM,
    ],
    ..Algorithms::NONE
};

/// AES-GCM with a 128-bit key (RFC 7518 §5.3): `A128GCM`.
pub const AES_128_GCM: Algorithms<'static> = Algorithms {
    content_encryption: &[ContentEncryptionAlgorithm::A128GCM],
    ..Algorithms::NONE
};

/// AES-GCM with a 256-bit key (RFC 7518 §5.3): `A256GCM`.
pub const AES_256_GCM: Algorithms<'static> = Algorithms {
    content_encryption: &[ContentEncryptionAlgorithm::A256GCM],
    ..Algorithms::NONE
};

/// A named, versioned validation profile.
///
/// RFC 8725 §3.12: one profile per kind of token, each refusing the others' (by `typ`,
/// audience, issuer, required claims or keys), is the application's to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The name, e.g. `strict`.
    pub name: String,
    /// Bumped whenever the profile accepts or refuses something new.
    pub version: u32,
    /// What a token may use.
    pub policy: Policy,
    /// What a JWT must claim.
    pub claims: ClaimsPolicy,
}

/// Profile names reserved for profiles not defined yet; asking for one by name fails
/// instead of silently giving a different profile.
pub const RESERVED: &[&str] = &["oauth-dpop", "openid-federation", "eudi-wallet"];

impl Profile {
    /// A profile called `name` that allows no algorithm yet; [`with`](Self::with) adds
    /// them. Everything else is strict: no key references in tokens, no extensions,
    /// no `kid` or `typ` required, 256 KiB at most; a JWT must have `exp`, with 60
    /// seconds of clock skew.
    pub fn new(name: impl Into<String>, version: u32) -> Profile {
        Profile {
            name: name.into(),
            version,
            policy: Policy {
                signature_algorithms: Vec::new(),
                signing_curves: Vec::new(),
                key_encryption_algorithms: Vec::new(),
                content_encryption_algorithms: Vec::new(),
                key_agreement_curves: Vec::new(),
                max_token_len: DEFAULT_MAX_TOKEN_LEN,
                understood_critical: Vec::new(),
                key_references: KeyReferences::default(),
                require_kid: false,
                typ: None,
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

    /// The default: modern public-key algorithms only, ES256 on P-256 ([`ECDSA_NIST`])
    /// and Ed25519 ([`ED25519`]); ECDH-ES on P-256 ([`ECDH_ES_P256`]) with A128GCM and
    /// A256GCM; otherwise as [`new`](Self::new). The polymorphic `EdDSA`, deprecated by
    /// RFC 9864, is not among them: the lists bind what a profile accepts and what it
    /// signs alike, and a deprecated name is not signed anew. RFC 8725 §3.2: only current
    /// algorithms, so no HMAC, which shares the verifier's key with every signer.
    pub fn strict() -> Profile {
        Profile::new("strict", 2)
            .with(&ECDSA_NIST)
            .with(&ED25519)
            .with(&ECDH_ES_P256)
            .with(&AES_128_GCM)
            .with(&AES_256_GCM)
    }

    /// Permissive, for interoperability tests: every algorithm and curve `registry` knows
    /// as available, every key reference, 1 MiB, no `exp` required. Never for production
    /// verification. Its lists are the registry's, not constants, so that it follows what
    /// a program registers (ti-jwz's brainpool names, for example).
    pub fn rfc7518_interop(registry: &Registry) -> Profile {
        let available = |s: Support| s == Support::Available;
        let signatures: Vec<_> = registry
            .signatures()
            .iter()
            .filter(|e| available(e.support))
            .map(|e| e.alg)
            .collect();
        let signing_curves: Vec<_> = registry
            .curves()
            .iter()
            .filter(|e| available(e.support))
            .filter(|e| e.key_type == KeyType::EC || e.key_type == KeyType::OKP)
            .map(|e| e.crv)
            .collect();
        let key_encryption: Vec<_> = registry
            .key_encryptions()
            .iter()
            .filter(|e| available(e.support))
            .map(|e| e.alg)
            .collect();
        let content_encryption: Vec<_> = registry
            .content_encryptions()
            .iter()
            .filter(|e| available(e.support))
            .map(|e| e.enc)
            .collect();
        let key_agreement_curves: Vec<_> = registry
            .curves()
            .iter()
            .filter(|e| available(e.support) && e.key_type == KeyType::EC)
            .map(|e| e.crv)
            .collect();
        let mut profile = Profile::new("rfc7518-interop", 2).with(&Algorithms {
            signatures: &signatures,
            signing_curves: &signing_curves,
            key_encryption: &key_encryption,
            content_encryption: &content_encryption,
            key_agreement_curves: &key_agreement_curves,
        });
        profile.policy.max_token_len = 1024 * 1024;
        profile.policy.key_references = KeyReferences::ALL;
        profile.claims.require_exp = false;
        profile
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

    /// This profile with the lists of `algorithms` appended, each value once; the name,
    /// the version and everything but the lists stay as they are.
    #[must_use]
    pub fn with(mut self, algorithms: &Algorithms<'_>) -> Profile {
        let policy = &mut self.policy;
        union_into(&mut policy.signature_algorithms, algorithms.signatures);
        union_into(&mut policy.signing_curves, algorithms.signing_curves);
        union_into(
            &mut policy.key_encryption_algorithms,
            algorithms.key_encryption,
        );
        union_into(
            &mut policy.content_encryption_algorithms,
            algorithms.content_encryption,
        );
        union_into(
            &mut policy.key_agreement_curves,
            algorithms.key_agreement_curves,
        );
        self
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
        // The prefix may be left out only where no other `/` follows: `application/a/b`
        // and `a/b` are different types.
        policy.typ = Some("a/b".into());
        for (typ, ok) in [("a/b", true), ("A/B", true), ("application/a/b", false)] {
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
    fn require_kid() {
        let registry = Registry::standard();
        let mut policy = Profile::strict().policy;
        policy.require_kid = true;
        let jws = |h: serde_json::Value| {
            policy
                .check_jws(&header(h), &registry)
                .map(|_| ())
                .map_err(|e| e.code())
        };
        assert_eq!(jws(json!({"alg": "ES256", "kid": "k1"})), Ok(()));
        for h in [json!({"alg": "ES256"}), json!({"alg": "ES256", "kid": ""})] {
            assert_eq!(jws(h.clone()), Err(ErrorCode::PolicyViolation), "{h}");
        }
        let jwe = |h: serde_json::Value| policy.check_jwe(&header(h), &registry).is_ok();
        assert!(jwe(
            json!({"alg": "ECDH-ES", "enc": "A256GCM", "kid": "k1"})
        ));
        assert!(!jwe(json!({"alg": "ECDH-ES", "enc": "A256GCM"})));
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

    /// An internal invariant of composition (ADR 0001, profiles): `with` appends each
    /// value once, in order, and leaves the name, the version and everything but the
    /// lists as they were.
    #[test]
    fn with_appends_each_value_once_and_changes_nothing_else() {
        let base = Profile::strict();
        let extended = base.clone().with(&ECDSA_NIST).with(&HMAC).with(&AES_GCM);
        assert_eq!(
            extended.policy.signature_algorithms,
            [
                SignatureAlgorithm::ES256,
                SignatureAlgorithm::ED25519,
                SignatureAlgorithm::HS256,
                SignatureAlgorithm::HS384,
                SignatureAlgorithm::HS512,
            ]
        );
        assert_eq!(
            extended.policy.signing_curves,
            [Curve::P256, Curve::ED25519]
        );
        assert_eq!(
            extended.policy.content_encryption_algorithms,
            [
                ContentEncryptionAlgorithm::A128GCM,
                ContentEncryptionAlgorithm::A256GCM,
                ContentEncryptionAlgorithm::A192GCM,
            ]
        );
        let lists_put_back = Profile {
            policy: Policy {
                signature_algorithms: base.policy.signature_algorithms.clone(),
                content_encryption_algorithms: base.policy.content_encryption_algorithms.clone(),
                ..extended.policy.clone()
            },
            ..extended
        };
        assert_eq!(lists_put_back, base);

        let twice = Profile::new("twice", 7).with(&Algorithms {
            signatures: &[SignatureAlgorithm::ES256, SignatureAlgorithm::ES256],
            signing_curves: &[Curve::P256],
            key_encryption: &[KeyEncryptionAlgorithm::DIR, KeyEncryptionAlgorithm::DIR],
            content_encryption: &[ContentEncryptionAlgorithm::A256GCM],
            key_agreement_curves: &[Curve::P256, Curve::P256],
        });
        assert_eq!(twice.name, "twice");
        assert_eq!(twice.version, 7);
        assert_eq!(
            twice.policy.signature_algorithms,
            [SignatureAlgorithm::ES256]
        );
        assert_eq!(twice.policy.signing_curves, [Curve::P256]);
        assert_eq!(
            twice.policy.key_encryption_algorithms,
            [KeyEncryptionAlgorithm::DIR]
        );
        assert_eq!(
            twice.policy.content_encryption_algorithms,
            [ContentEncryptionAlgorithm::A256GCM]
        );
        assert_eq!(twice.policy.key_agreement_curves, [Curve::P256]);
    }

    /// The same invariant at its edge: the empty bundle changes no profile.
    #[test]
    fn algorithms_none_changes_nothing() {
        let registry = Registry::standard();
        for profile in [
            Profile::new("empty", 1),
            Profile::strict(),
            Profile::rfc7518_interop(&registry),
        ] {
            assert_eq!(profile.clone().with(&Algorithms::NONE), profile);
        }
    }

    #[test]
    fn strict_is_its_constants_on_the_strict_defaults() {
        let strict = Profile::strict();
        assert_eq!((strict.name.as_str(), strict.version), ("strict", 2));
        assert_eq!(
            strict.policy.signature_algorithms,
            [SignatureAlgorithm::ES256, SignatureAlgorithm::ED25519]
        );
        assert_eq!(strict.policy.signing_curves, [Curve::P256, Curve::ED25519]);
        assert_eq!(
            strict.policy.key_encryption_algorithms,
            [
                KeyEncryptionAlgorithm::ECDH_ES,
                KeyEncryptionAlgorithm::ECDH_ES_A128KW,
                KeyEncryptionAlgorithm::ECDH_ES_A256KW,
            ]
        );
        assert_eq!(
            strict.policy.content_encryption_algorithms,
            [
                ContentEncryptionAlgorithm::A128GCM,
                ContentEncryptionAlgorithm::A256GCM
            ]
        );
        assert_eq!(strict.policy.key_agreement_curves, [Curve::P256]);
        let defaults = Profile::new("strict", 2);
        assert_eq!(strict.claims, defaults.claims);
        assert_eq!(
            Policy {
                signature_algorithms: Vec::new(),
                signing_curves: Vec::new(),
                key_encryption_algorithms: Vec::new(),
                content_encryption_algorithms: Vec::new(),
                key_agreement_curves: Vec::new(),
                ..strict.policy
            },
            defaults.policy
        );
        assert_eq!(defaults.policy.max_token_len, DEFAULT_MAX_TOKEN_LEN);
        assert_eq!(defaults.policy.key_references, KeyReferences::default());
        assert!(defaults.claims.require_exp);
        assert_eq!(defaults.claims.leeway, 60);
    }

    #[test]
    fn rfc7518_interop_lists_what_the_registry_has_available() {
        let interop = Profile::rfc7518_interop(&Registry::standard());
        let policy = &interop.policy;
        assert!(
            policy
                .signature_algorithms
                .contains(&SignatureAlgorithm::ES256)
        );
        assert!(
            policy
                .signature_algorithms
                .contains(&SignatureAlgorithm::EDDSA)
        );
        assert!(
            !policy
                .signature_algorithms
                .contains(&SignatureAlgorithm::ES384)
        );
        assert_eq!(
            policy
                .signature_algorithms
                .contains(&SignatureAlgorithm::HS256),
            cfg!(feature = "hmac")
        );
        assert_eq!(policy.signing_curves, [Curve::P256, Curve::ED25519]);
        assert_eq!(policy.key_agreement_curves, [Curve::P256]);
        assert!(
            policy
                .key_encryption_algorithms
                .contains(&KeyEncryptionAlgorithm::A192KW)
        );
        assert!(
            !policy
                .key_encryption_algorithms
                .contains(&KeyEncryptionAlgorithm::RSA_OAEP)
        );
        assert_eq!(policy.content_encryption_algorithms.len(), 3);
        assert_eq!(policy.max_token_len, 1024 * 1024);
        assert_eq!(policy.key_references, KeyReferences::ALL);
        assert!(!interop.claims.require_exp);
        assert_eq!(
            Profile::by_name("rfc7518-interop", &Registry::standard()),
            Ok(interop)
        );
        assert_eq!(
            Profile::by_name("strict", &Registry::standard()),
            Ok(Profile::strict())
        );
        assert_eq!(
            Profile::by_name("oauth-dpop", &Registry::standard()).map_err(|e| e.code()),
            Err(ErrorCode::UnsupportedAlgorithm)
        );
    }

    /// RFC 8725 §3.1: the profile decides the algorithms, for signing as for
    /// verification; RFC 7518 §3.4: a key that states no curve is on its algorithm's
    /// registered one; RFC 8037 §3.1: EdDSA's curve is the key's, so one that states none
    /// is refused; RFC 9864 §2.2: Ed25519 names its curve, as ES256 does.
    #[test]
    fn rfc_8725_3_1_a_signing_key_is_bound_to_the_profiles_algorithms_and_curves() {
        let registry = Registry::standard();
        let strict = Profile::strict().policy;
        assert_eq!(
            strict
                .check_signing_key(SignatureAlgorithm::EDDSA, Some(Curve::ED25519), &registry)
                .map_err(|e| e.code()),
            Err(ErrorCode::PolicyViolation),
            "strict lists Ed25519, not the deprecated EdDSA"
        );
        let with_eddsa = Profile::strict().with(&EDDSA).policy;
        let check = |alg, curve| {
            with_eddsa
                .check_signing_key(alg, curve, &registry)
                .map_err(|e| e.code())
        };
        assert_eq!(check(SignatureAlgorithm::ED25519, None), Ok(()));
        assert_eq!(
            check(SignatureAlgorithm::ED25519, Some(Curve::ED448)),
            Err(ErrorCode::PolicyViolation)
        );
        assert_eq!(check(SignatureAlgorithm::ES256, None), Ok(()));
        assert_eq!(check(SignatureAlgorithm::ES256, Some(Curve::P256)), Ok(()));
        assert_eq!(
            check(SignatureAlgorithm::ES256, Some(Curve::new("BP-256"))),
            Err(ErrorCode::PolicyViolation)
        );
        assert_eq!(
            check(SignatureAlgorithm::EDDSA, Some(Curve::ED25519)),
            Ok(())
        );
        assert_eq!(
            check(SignatureAlgorithm::EDDSA, Some(Curve::ED448)),
            Err(ErrorCode::PolicyViolation)
        );
        assert_eq!(
            check(SignatureAlgorithm::EDDSA, None),
            Err(ErrorCode::PolicyViolation)
        );
        assert_eq!(
            check(SignatureAlgorithm::ES384, Some(Curve::P384)),
            Err(ErrorCode::UnsupportedAlgorithm)
        );
        assert_eq!(
            check(SignatureAlgorithm::PS256, None),
            Err(ErrorCode::UnsupportedAlgorithm)
        );

        // No signing curve listed: the algorithm alone admits no key.
        let no_curves = Profile::new("no curves", 1)
            .with(&Algorithms {
                signatures: &[SignatureAlgorithm::ES256],
                ..Algorithms::NONE
            })
            .policy;
        assert_eq!(
            no_curves
                .check_signing_key(SignatureAlgorithm::ES256, None, &registry)
                .map_err(|e| e.code()),
            Err(ErrorCode::PolicyViolation)
        );

        // HMAC keys have no curve: the algorithm alone binds them.
        let hmac = Profile::new("hmac", 1).with(&HMAC).policy;
        let expected = if cfg!(feature = "hmac") {
            Ok(())
        } else {
            Err(ErrorCode::UnsupportedAlgorithm)
        };
        for curve in [None, Some(Curve::P256)] {
            assert_eq!(
                hmac.check_signing_key(SignatureAlgorithm::HS256, curve, &registry)
                    .map_err(|e| e.code()),
                expected
            );
        }
        if cfg!(feature = "hmac") {
            assert_eq!(
                check(SignatureAlgorithm::HS256, None),
                Err(ErrorCode::PolicyViolation)
            );
        }
    }

    /// RFC 8725 §3.1 for JWE: what is produced is held to the lists a received header
    /// is held to, the recipient's curve to the key-agreement curves.
    #[test]
    fn rfc_8725_3_1_encryption_is_bound_to_the_profiles_lists() {
        let strict = Profile::strict().policy;
        let check = |alg, enc, curve| {
            strict
                .check_encryption(alg, enc, curve)
                .map_err(|e| e.code())
        };
        let (es, a256) = (
            KeyEncryptionAlgorithm::ECDH_ES,
            ContentEncryptionAlgorithm::A256GCM,
        );
        assert_eq!(check(es, a256, Some(Curve::P256)), Ok(()));
        assert_eq!(check(es, a256, None), Ok(()));
        for (alg, enc, curve) in [
            (KeyEncryptionAlgorithm::DIR, a256, None),
            (es, ContentEncryptionAlgorithm::A192GCM, Some(Curve::P256)),
            (es, a256, Some(Curve::new("BP-256"))),
        ] {
            assert_eq!(
                check(alg, enc, curve),
                Err(ErrorCode::PolicyViolation),
                "{alg:?} {enc:?} {curve:?}"
            );
        }
    }
}
