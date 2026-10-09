//! brainpoolP256r1 for jwz: the JWS algorithm `BP256R1` and the JWK curve `BP-256`, as
//! gematik uses them on existing TI interfaces (IDP, ePA and E-Rezept VAU handshakes,
//! SMC-B and HBA keys). Legacy support only: new components use P-256 and must not
//! depend on this crate (`just brainpool-absent <crate>` checks that).
//!
//! Neither identifier is registered with IANA; they are gematik's (gemSpec_Krypt
//! V2.50.0), mirrored by `go/brainpool/josebp` in this repository. Brainpool ECDH-ES
//! uses the standard `ECDH-ES` names with an `epk` on `BP-256`.
//!
//! This crate adds names and, from milestone 1 stage S5, the key implementations; it
//! holds no parsing, header or policy code, which stay in jwz for every curve.
#![no_std]
#![forbid(unsafe_code)]

use jwz::jwa::{
    Curve, CurveEntry, HashAlgorithm, KeyType, Registry, RegistryError, SignatureAlgorithm,
    SignatureEntry, Support,
};

/// ECDSA over brainpoolP256r1 with SHA-256, signature `r || s` (gemSpec_Krypt V2.50.0).
pub const BP256R1: SignatureAlgorithm = SignatureAlgorithm::new("BP256R1");

/// The JWK `crv` of brainpoolP256r1 keys.
pub const BP_256: Curve = Curve::new("BP-256");

/// Adds `BP-256` and `BP256R1` to `registry`.
///
/// # Errors
///
/// [`RegistryError::Duplicate`] if either name is already registered.
pub fn register(registry: &mut Registry) -> Result<(), RegistryError> {
    registry.register_curve(CurveEntry {
        crv: BP_256,
        key_type: KeyType::EC,
        coordinate_len: 32,
        support: Support::Available,
    })?;
    registry.register_signature(SignatureEntry {
        alg: BP256R1,
        key_type: KeyType::EC,
        curve: Some(BP_256),
        hash: Some(HashAlgorithm::Sha256),
        support: Support::Available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_bp256r1_and_its_curve_once() {
        let mut registry = Registry::standard();
        assert!(registry.signature("BP256R1").is_none());
        register(&mut registry).unwrap();
        let entry = registry.signature("BP256R1").unwrap();
        assert_eq!(entry.curve, Some(BP_256));
        assert_eq!(registry.curve("BP-256").map(|c| c.coordinate_len), Some(32));
        assert_eq!(
            register(&mut registry),
            Err(RegistryError::Duplicate("BP-256"))
        );
    }
}
