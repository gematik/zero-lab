//! gemSpec_Krypt admissibility of an end-entity public key (Tab_KRYPT_002/002a for
//! non-QES, Tab_KRYPT_003/003a for QES).
//!
//! The tables admit ECDSA on brainpoolP256r1 or P-256 and RSA with 2048 bit, the latter
//! until the end of 2025. The spec's own enforcement text draws the line at 3000 bit, so
//! longer RSA keys are admissible without a date. Everything else — other curves,
//! shorter RSA, other algorithms — never appeared in a table. Only the key's parameters
//! are read, so RSA keys are classified without any RSA implementation.

use core::fmt;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use der::asn1::UintRef;
use der::{Decode, Sequence};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::time::Timestamp;

/// What gemSpec_Krypt says about an end-entity public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyStatus {
    /// Listed in the current tables without reservation.
    Admissible,
    /// Once listed, but past its "zulässig bis" date. gemSpec_Krypt enforces that date
    /// by removing the issuing CAs from the TSL and tells verifiers not to (A_23458), so
    /// validation reports it as a warning, never as an error.
    PhasedOut,
    /// Never listed for a TI certificate; no TSP issues such a certificate.
    NotAdmissible,
}

impl KeyStatus {
    /// Lowercase name, as in `gempki`: `admissible`, `phased out`, `not admissible`.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyStatus::Admissible => "admissible",
            KeyStatus::PhasedOut => "phased out",
            KeyStatus::NotAdmissible => "not admissible",
        }
    }
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// End of 2025, the "zulässig bis" of RSA-2048 in Tab_KRYPT_002. Tab_KRYPT_003 (QES)
/// defers to SOG-IS instead, which retires RSA-2048 on the same horizon, so one date
/// serves both.
pub const RSA_2048_ADMISSIBLE_UNTIL: Timestamp = Timestamp(1_767_225_599);

/// Classifies `key` as of `at` and describes it for messages (`ECDSA brainpoolP256r1`,
/// `RSA 2048`).
pub fn classify_key(key: &SubjectPublicKeyInfoOwned, at: Timestamp) -> (KeyStatus, String) {
    let algorithm = key.algorithm.oid;
    if algorithm == ID_EC_PUBLIC_KEY {
        let Some(curve) = key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
        else {
            return (KeyStatus::NotAdmissible, "ECDSA (unknown curve)".into());
        };
        let name = curve_name(&curve).map_or_else(|| curve.to_string(), str::to_owned);
        let status = if name == "brainpoolP256r1" || name == "P-256" {
            KeyStatus::Admissible
        } else {
            KeyStatus::NotAdmissible
        };
        return (status, format!("ECDSA {name}"));
    }
    if algorithm == RSA_ENCRYPTION {
        let Some(bits) = rsa_modulus_bits(key.subject_public_key.raw_bytes()) else {
            return (KeyStatus::NotAdmissible, "RSA (no modulus)".into());
        };
        let status = match bits {
            ..2048 => KeyStatus::NotAdmissible,
            2048..3000 if at > RSA_2048_ADMISSIBLE_UNTIL => KeyStatus::PhasedOut,
            _ => KeyStatus::Admissible,
        };
        return (status, format!("RSA {bits}"));
    }
    let name = algorithm_name(&algorithm).map_or_else(|| algorithm.to_string(), str::to_owned);
    (KeyStatus::NotAdmissible, name)
}

fn curve_name(curve: &ObjectIdentifier) -> Option<&'static str> {
    Some(match curve.to_string().as_str() {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.33" => "P-224",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        _ => return None,
    })
}

fn algorithm_name(algorithm: &ObjectIdentifier) -> Option<&'static str> {
    Some(match algorithm.to_string().as_str() {
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.10040.4.1" => "DSA",
        _ => return None,
    })
}

#[derive(Sequence)]
#[allow(
    dead_code,
    reason = "decoded to match RSAPublicKey; only the modulus is read"
)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

fn rsa_modulus_bits(public_key: &[u8]) -> Option<usize> {
    let key = RsaPublicKey::from_der(public_key).ok()?;
    let bytes = key.modulus.as_bytes();
    let first = *bytes.first()?;
    Some(bytes.len() * 8 - first.leading_zeros() as usize)
}

#[cfg(test)]
pub(crate) mod tests {
    use der::Encode;
    use der::asn1::{Any, BitString};
    use x509_cert::spki::AlgorithmIdentifierOwned;

    use super::*;

    /// An EC key on the curve `oid` with a dummy point of `len` bytes; classification
    /// reads only the curve.
    pub(crate) fn ec_spki(oid: &str, len: usize) -> SubjectPublicKeyInfoOwned {
        let mut point = vec![0x42; len];
        point[0] = 0x04;
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::from(&ObjectIdentifier::new_unwrap(oid))),
            },
            subject_public_key: BitString::from_bytes(&point).unwrap(),
        }
    }

    fn rsa_spki(bits: usize) -> SubjectPublicKeyInfoOwned {
        let mut modulus = vec![0xab; bits / 8];
        modulus[0] = 0x80;
        let key = RsaPublicKey {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(&[0x01, 0x00, 0x01]).unwrap(),
        };
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: RSA_ENCRYPTION,
                parameters: Some(Any::null()),
            },
            subject_public_key: BitString::from_bytes(&key.to_der().unwrap()).unwrap(),
        }
    }

    fn other_spki(oid: &str) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(oid),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&[0; 32]).unwrap(),
        }
    }

    #[test]
    fn classification_table() {
        let before = Timestamp(RSA_2048_ADMISSIBLE_UNTIL.0 - 12 * 3600);
        let after = Timestamp(RSA_2048_ADMISSIBLE_UNTIL.0 + 1);
        for (key, at, want, desc) in [
            (
                ec_spki("1.3.36.3.3.2.8.1.1.7", 65),
                after,
                KeyStatus::Admissible,
                "ECDSA brainpoolP256r1",
            ),
            (
                ec_spki("1.2.840.10045.3.1.7", 65),
                after,
                KeyStatus::Admissible,
                "ECDSA P-256",
            ),
            (
                ec_spki("1.3.132.0.33", 57),
                after,
                KeyStatus::NotAdmissible,
                "ECDSA P-224",
            ),
            (
                ec_spki("1.3.132.0.34", 97),
                after,
                KeyStatus::NotAdmissible,
                "ECDSA P-384",
            ),
            (
                ec_spki("1.3.132.0.35", 133),
                after,
                KeyStatus::NotAdmissible,
                "ECDSA P-521",
            ),
            (
                ec_spki("1.3.36.3.3.2.8.1.1.11", 97),
                after,
                KeyStatus::NotAdmissible,
                "ECDSA brainpoolP384r1",
            ),
            (rsa_spki(1024), before, KeyStatus::NotAdmissible, "RSA 1024"),
            (rsa_spki(2048), before, KeyStatus::Admissible, "RSA 2048"),
            (rsa_spki(2048), after, KeyStatus::PhasedOut, "RSA 2048"),
            (rsa_spki(3072), after, KeyStatus::Admissible, "RSA 3072"),
            (
                other_spki("1.3.101.112"),
                after,
                KeyStatus::NotAdmissible,
                "Ed25519",
            ),
            (
                other_spki("1.2.3.4"),
                after,
                KeyStatus::NotAdmissible,
                "1.2.3.4",
            ),
        ] {
            assert_eq!(classify_key(&key, at), (want, desc.to_owned()), "{desc}");
        }
    }

    #[test]
    fn malformed_keys_are_not_admissible() {
        let mut no_curve = ec_spki("1.2.840.10045.3.1.7", 65);
        no_curve.algorithm.parameters = None;
        assert_eq!(
            classify_key(&no_curve, Timestamp(0)),
            (KeyStatus::NotAdmissible, "ECDSA (unknown curve)".to_owned())
        );
        let mut garbage_rsa = rsa_spki(2048);
        garbage_rsa.subject_public_key = BitString::from_bytes(b"junk").unwrap();
        assert_eq!(
            classify_key(&garbage_rsa, Timestamp(0)),
            (KeyStatus::NotAdmissible, "RSA (no modulus)".to_owned())
        );
    }

    #[test]
    fn rsa_date_is_end_of_2025() {
        // 2025-12-31T23:59:59Z
        assert_eq!(RSA_2048_ADMISSIBLE_UNTIL.0, 1_767_225_599);
    }
}
