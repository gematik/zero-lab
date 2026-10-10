//! JSON Web Keys (RFC 7517) and JWK Sets: EC, OKP, oct and RSA keys, the RFC 7638
//! thumbprint, and strict parsing (duplicate members, base64url).
//!
//! Parsing checks structure only; [`Jwk::check`] then checks a key against a
//! [`Registry`]: that its curve is known for its key type and every component has the
//! length RFC 7518 §6.2.1 / RFC 8037 §2 fixes. Whether the point is on the curve is the
//! crypto backend's check when the key is used. RSA keys are data only in milestone 1.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::b64;
use crate::crypto::Hash;
use crate::error::{Error, ErrorCode};
use crate::json;
use crate::jwa::{Curve, KeyType, Registry};

/// Private key material: zeroized on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wraps `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    /// The bytes; callers keep them in zeroizing storage.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// An elliptic-curve key (RFC 7518 §6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcKey {
    /// `crv`.
    pub crv: String,
    /// `x`, big-endian, the curve's coordinate length.
    pub x: Vec<u8>,
    /// `y`, big-endian, the curve's coordinate length.
    pub y: Vec<u8>,
    /// `d`, the private scalar.
    pub d: Option<Secret>,
}

impl EcKey {
    /// The public key `x`, `y` on `crv` from the SEC1 uncompressed point `point`
    /// (`0x04 || x || y`).
    pub fn from_point(crv: &str, point: &[u8]) -> EcKey {
        let coordinates = point.get(1..).unwrap_or_default();
        let (x, y) = coordinates.split_at(coordinates.len() / 2);
        EcKey {
            crv: crv.to_string(),
            x: x.to_vec(),
            y: y.to_vec(),
            d: None,
        }
    }

    /// The public key as a SEC1 uncompressed point, the form the crypto traits take.
    pub fn point(&self) -> Vec<u8> {
        let mut point = Vec::with_capacity(1 + self.x.len() + self.y.len());
        point.push(0x04);
        point.extend_from_slice(&self.x);
        point.extend_from_slice(&self.y);
        point
    }
}

/// An octet key pair (RFC 8037 §2): Ed25519, Ed448, X25519, X448.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkpKey {
    /// `crv`.
    pub crv: String,
    /// `x`, the public key.
    pub x: Vec<u8>,
    /// `d`, the private key.
    pub d: Option<Secret>,
}

/// A symmetric key (RFC 7518 §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OctKey {
    /// `k`.
    pub k: Secret,
}

/// The private part of an RSA key (RFC 7518 §6.3.2); only `d` is required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivate {
    /// `d`.
    pub d: Secret,
    /// `p`, `q`, `dp`, `dq`, `qi`, present together or not at all.
    pub primes: Option<[Secret; 5]>,
}

/// An RSA key (RFC 7518 §6.3); data model only in milestone 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaKey {
    /// `n`.
    pub n: Vec<u8>,
    /// `e`.
    pub e: Vec<u8>,
    /// The private part.
    pub private: Option<RsaPrivate>,
}

/// The key itself; its variant is the `kty`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyMaterial {
    /// `kty` `EC`.
    Ec(EcKey),
    /// `kty` `OKP`.
    Okp(OkpKey),
    /// `kty` `oct`.
    Oct(OctKey),
    /// `kty` `RSA`.
    Rsa(RsaKey),
}

/// A JSON Web Key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// The key.
    pub material: KeyMaterial,
    /// `kid`.
    pub kid: Option<String>,
    /// `alg`: the algorithm the key is meant for (RFC 7517 §4.4).
    pub alg: Option<String>,
    /// `use` (RFC 7517 §4.2).
    pub key_use: Option<String>,
    /// `key_ops` (RFC 7517 §4.3).
    pub key_ops: Option<Vec<String>>,
    /// `x5c`: certificates, standard base64 DER, leaf first (RFC 7517 §4.7).
    pub x5c: Option<Vec<String>>,
    /// `x5t#S256` (RFC 7517 §4.9).
    pub x5t_s256: Option<String>,
}

impl Jwk {
    /// A key with no optional members.
    pub fn new(material: KeyMaterial) -> Self {
        Jwk {
            material,
            kid: None,
            alg: None,
            key_use: None,
            key_ops: None,
            x5c: None,
            x5t_s256: None,
        }
    }

    /// The `kty`.
    pub fn key_type(&self) -> KeyType {
        match self.material {
            KeyMaterial::Ec(_) => KeyType::EC,
            KeyMaterial::Okp(_) => KeyType::OKP,
            KeyMaterial::Oct(_) => KeyType::OCT,
            KeyMaterial::Rsa(_) => KeyType::RSA,
        }
    }

    /// The `crv`, for EC and OKP keys.
    pub fn crv(&self) -> Option<&str> {
        match &self.material {
            KeyMaterial::Ec(k) => Some(&k.crv),
            KeyMaterial::Okp(k) => Some(&k.crv),
            KeyMaterial::Oct(_) | KeyMaterial::Rsa(_) => None,
        }
    }

    /// Whether the key holds private material.
    pub fn is_private(&self) -> bool {
        match &self.material {
            KeyMaterial::Ec(k) => k.d.is_some(),
            KeyMaterial::Okp(k) => k.d.is_some(),
            KeyMaterial::Oct(_) => true,
            KeyMaterial::Rsa(k) => k.private.is_some(),
        }
    }

    /// Parses the JWK in `text`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Json`], [`ErrorCode::DuplicateMember`], [`ErrorCode::Base64`],
    /// [`ErrorCode::MissingMember`], [`ErrorCode::InvalidMember`], or
    /// [`ErrorCode::UnsupportedKeyType`] for a `kty` other than EC, OKP, oct and RSA.
    pub fn parse(text: &str) -> Result<Jwk, Error> {
        let members = json::parse_object(text.as_bytes(), "jwk")?;
        Jwk::from_members(&members)
    }

    fn from_members(m: &Map<String, Value>) -> Result<Jwk, Error> {
        // RFC 7517 §4.1: kty is required and case-sensitive.
        let material = match required_str(m, "kty")? {
            "EC" => KeyMaterial::Ec(EcKey {
                crv: required_str(m, "crv")?.to_string(),
                x: required_b64(m, "x")?,
                y: required_b64(m, "y")?,
                d: optional_secret(m, "d")?,
            }),
            "OKP" => KeyMaterial::Okp(OkpKey {
                crv: required_str(m, "crv")?.to_string(),
                x: required_b64(m, "x")?,
                d: optional_secret(m, "d")?,
            }),
            "oct" => KeyMaterial::Oct(OctKey {
                k: Secret::new(required_b64(m, "k")?),
            }),
            "RSA" => KeyMaterial::Rsa(rsa_from_members(m)?),
            _ => return Err(Error::new(ErrorCode::UnsupportedKeyType, "kty")),
        };
        Ok(Jwk {
            material,
            kid: optional_str(m, "kid")?,
            alg: optional_str(m, "alg")?,
            key_use: optional_str(m, "use")?,
            key_ops: optional_str_array(m, "key_ops")?,
            x5c: optional_str_array(m, "x5c")?,
            x5t_s256: optional_str(m, "x5t#S256")?,
        })
    }

    /// Checks the key against `registry`: a known curve for its key type and component
    /// lengths as RFC 7518 §6.2.1.2 / §6.2.2.1 and RFC 8037 §2 fix them.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnknownCurve`] or [`ErrorCode::KeyLength`].
    pub fn check(&self, registry: &Registry) -> Result<(), Error> {
        let curve_len = |crv: &str, kty: KeyType| -> Result<usize, Error> {
            let entry = registry
                .curve(crv)
                .filter(|e| e.key_type == kty)
                .ok_or(Error::new(ErrorCode::UnknownCurve, "crv"))?;
            Ok(entry.coordinate_len)
        };
        let exact = |bytes: &[u8], len: usize, context: &'static str| -> Result<(), Error> {
            if bytes.len() == len {
                Ok(())
            } else {
                Err(Error::new(ErrorCode::KeyLength, context))
            }
        };
        match &self.material {
            KeyMaterial::Ec(k) => {
                // RFC 7518 §6.2.1.2: x and y MUST be the full coordinate size;
                // §6.2.2.1: d MUST be ceiling(log-base-2(n)/8) octets.
                let len = curve_len(&k.crv, KeyType::EC)?;
                exact(&k.x, len, "x")?;
                exact(&k.y, len, "y")?;
                if let Some(d) = &k.d {
                    exact(d.expose(), len, "d")?;
                }
            }
            KeyMaterial::Okp(k) => {
                // RFC 8037 §2: x and d are the curve's raw key encodings.
                let len = curve_len(&k.crv, KeyType::OKP)?;
                exact(&k.x, len, "x")?;
                if let Some(d) = &k.d {
                    exact(d.expose(), len, "d")?;
                }
            }
            KeyMaterial::Oct(k) => {
                if k.k.expose().is_empty() {
                    return Err(Error::new(ErrorCode::KeyLength, "k"));
                }
            }
            KeyMaterial::Rsa(k) => {
                if k.n.is_empty() || k.e.is_empty() {
                    return Err(Error::new(ErrorCode::KeyLength, "n"));
                }
            }
        }
        Ok(())
    }

    /// The key without its private parts; a symmetric key has none to remove and is
    /// returned unchanged.
    #[must_use]
    pub fn public(&self) -> Jwk {
        let material = match &self.material {
            KeyMaterial::Ec(k) => KeyMaterial::Ec(EcKey {
                d: None,
                ..k.clone()
            }),
            KeyMaterial::Okp(k) => KeyMaterial::Okp(OkpKey {
                d: None,
                ..k.clone()
            }),
            KeyMaterial::Oct(k) => KeyMaterial::Oct(k.clone()),
            KeyMaterial::Rsa(k) => KeyMaterial::Rsa(RsaKey {
                private: None,
                ..k.clone()
            }),
        };
        Jwk {
            material,
            ..self.clone()
        }
    }

    /// The key as a JSON object, private parts included if present.
    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        put(&mut m, "kty", self.key_type().as_str());
        match &self.material {
            KeyMaterial::Ec(k) => {
                put(&mut m, "crv", &k.crv);
                put(&mut m, "x", &b64::encode(&k.x));
                put(&mut m, "y", &b64::encode(&k.y));
                if let Some(d) = &k.d {
                    put(&mut m, "d", &b64::encode(d.expose()));
                }
            }
            KeyMaterial::Okp(k) => {
                put(&mut m, "crv", &k.crv);
                put(&mut m, "x", &b64::encode(&k.x));
                if let Some(d) = &k.d {
                    put(&mut m, "d", &b64::encode(d.expose()));
                }
            }
            KeyMaterial::Oct(k) => put(&mut m, "k", &b64::encode(k.k.expose())),
            KeyMaterial::Rsa(k) => {
                put(&mut m, "n", &b64::encode(&k.n));
                put(&mut m, "e", &b64::encode(&k.e));
                if let Some(private) = &k.private {
                    put(&mut m, "d", &b64::encode(private.d.expose()));
                    if let Some([p, q, dp, dq, qi]) = &private.primes {
                        for (name, value) in
                            [("p", p), ("q", q), ("dp", dp), ("dq", dq), ("qi", qi)]
                        {
                            put(&mut m, name, &b64::encode(value.expose()));
                        }
                    }
                }
            }
        }
        for (name, value) in [
            ("kid", &self.kid),
            ("alg", &self.alg),
            ("use", &self.key_use),
            ("x5t#S256", &self.x5t_s256),
        ] {
            if let Some(value) = value {
                put(&mut m, name, value);
            }
        }
        for (name, values) in [("key_ops", &self.key_ops), ("x5c", &self.x5c)] {
            if let Some(values) = values {
                m.insert(
                    name.to_string(),
                    Value::Array(values.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        Value::Object(m).to_string()
    }

    /// The RFC 7638 thumbprint: the base64url hash of the key's required public members
    /// in lexicographic order, without whitespace.
    pub fn thumbprint(&self, hash: &dyn Hash) -> String {
        // RFC 7638 §3.2: the required members of each key type, sorted by name.
        let members: Vec<(&str, String)> = match &self.material {
            KeyMaterial::Ec(k) => alloc::vec![
                ("crv", k.crv.clone()),
                ("kty", "EC".to_string()),
                ("x", b64::encode(&k.x)),
                ("y", b64::encode(&k.y)),
            ],
            KeyMaterial::Okp(k) => alloc::vec![
                ("crv", k.crv.clone()),
                ("kty", "OKP".to_string()),
                ("x", b64::encode(&k.x)),
            ],
            KeyMaterial::Oct(k) => {
                alloc::vec![("k", b64::encode(k.k.expose())), ("kty", "oct".to_string()),]
            }
            KeyMaterial::Rsa(k) => alloc::vec![
                ("e", b64::encode(&k.e)),
                ("kty", "RSA".to_string()),
                ("n", b64::encode(&k.n)),
            ],
        };
        let mut canonical = String::from("{");
        for (i, (name, value)) in members.iter().enumerate() {
            if i > 0 {
                canonical.push(',');
            }
            canonical.push_str(&Value::String((*name).to_string()).to_string());
            canonical.push(':');
            canonical.push_str(&Value::String(value.clone()).to_string());
        }
        canonical.push('}');
        b64::encode(&hash.digest(&[canonical.as_bytes()]))
    }
}

/// A JWK Set (RFC 7517 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwkSet {
    /// The keys, in order.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parses a JWK Set. Keys with a `kty` this library does not handle are skipped, as
    /// RFC 7517 §5 recommends; any other malformed key fails the whole set.
    ///
    /// # Errors
    ///
    /// As [`Jwk::parse`], and [`ErrorCode::MissingMember`] without `keys`.
    pub fn parse(text: &str) -> Result<JwkSet, Error> {
        let members = json::parse_object(text.as_bytes(), "jwk set")?;
        let entries = members
            .get("keys")
            .ok_or(Error::new(ErrorCode::MissingMember, "keys"))?
            .as_array()
            .ok_or(Error::new(ErrorCode::InvalidMember, "keys"))?;
        let mut keys = Vec::new();
        for entry in entries {
            let object = entry
                .as_object()
                .ok_or(Error::new(ErrorCode::InvalidMember, "keys"))?;
            match Jwk::from_members(object) {
                Ok(key) => keys.push(key),
                Err(e) if e.code() == ErrorCode::UnsupportedKeyType => {}
                Err(e) => return Err(e),
            }
        }
        Ok(JwkSet { keys })
    }

    /// The keys with `kid`.
    pub fn by_kid<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Jwk> + 'a {
        self.keys
            .iter()
            .filter(move |key| key.kid.as_deref() == Some(kid))
    }
}

/// Whether `crv` names a curve of `kty` in `registry`.
pub fn curve_for(registry: &Registry, crv: &str, kty: KeyType) -> Option<Curve> {
    registry
        .curve(crv)
        .filter(|e| e.key_type == kty)
        .map(|e| e.crv)
}

fn put(m: &mut Map<String, Value>, name: &str, value: &str) {
    m.insert(name.to_string(), Value::String(value.to_string()));
}

fn required_str<'a>(m: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, Error> {
    m.get(name)
        .ok_or(Error::new(ErrorCode::MissingMember, name))?
        .as_str()
        .ok_or(Error::new(ErrorCode::InvalidMember, name))
}

fn optional_str(m: &Map<String, Value>, name: &'static str) -> Result<Option<String>, Error> {
    match m.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::new(ErrorCode::InvalidMember, name)),
    }
}

fn optional_str_array(
    m: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<Vec<String>>, Error> {
    let Some(value) = m.get(name) else {
        return Ok(None);
    };
    let invalid = Error::new(ErrorCode::InvalidMember, name);
    let items = value.as_array().ok_or(invalid)?;
    items
        .iter()
        .map(|item| item.as_str().map(ToString::to_string).ok_or(invalid))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn required_b64(m: &Map<String, Value>, name: &'static str) -> Result<Vec<u8>, Error> {
    b64::decode(required_str(m, name)?, name)
}

fn optional_secret(m: &Map<String, Value>, name: &'static str) -> Result<Option<Secret>, Error> {
    match m.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(Secret::new(b64::decode(s, name)?))),
        Some(_) => Err(Error::new(ErrorCode::InvalidMember, name)),
    }
}

fn rsa_from_members(m: &Map<String, Value>) -> Result<RsaKey, Error> {
    let private = match optional_secret(m, "d")? {
        None => None,
        Some(d) => {
            let parts = [
                optional_secret(m, "p")?,
                optional_secret(m, "q")?,
                optional_secret(m, "dp")?,
                optional_secret(m, "dq")?,
                optional_secret(m, "qi")?,
            ];
            // RFC 7518 §6.3.2: the CRT parameters come together or not at all.
            let primes = match parts {
                [Some(p), Some(q), Some(dp), Some(dq), Some(qi)] => Some([p, q, dp, dq, qi]),
                [None, None, None, None, None] => None,
                _ => return Err(Error::new(ErrorCode::MissingMember, "p")),
            };
            Some(RsaPrivate { d, primes })
        }
    };
    Ok(RsaKey {
        n: required_b64(m, "n")?,
        e: required_b64(m, "e")?,
        private,
    })
}
