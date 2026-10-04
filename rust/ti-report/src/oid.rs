//! OIDs with the names gemSpec_OID gives them.

use const_oid::ObjectIdentifier;
use serde::Serialize;

/// An OID with its gemSpec_OID description, where the TI defines one.
#[derive(Clone, Debug, Serialize)]
pub struct OidInfo {
    /// Dotted form.
    pub oid: String,
    /// The description from gemSpec_OID.
    pub name: Option<&'static str>,
}

impl OidInfo {
    /// Looks `oid` up in the gemSpec_OID tables.
    pub fn new(oid: &ObjectIdentifier) -> Self {
        OidInfo {
            oid: oid.to_string(),
            name: ti_pki::oid::lookup(oid)
                .map(|info| info.description)
                .filter(|d| !d.is_empty()),
        }
    }
}

/// A certificate type OID a TSL states for a CA (Tab_PKI_405), with its gemSpec_OID
/// reference name, e.g. `oid_smc_b_osig`, and type name.
#[derive(Clone, Debug, Serialize)]
pub struct TypeOid {
    /// Dotted form.
    pub oid: String,
    /// The gemSpec_OID reference name; absent for an OID the tables do not declare.
    pub reference: Option<&'static str>,
    /// The type name from gemSpec_OID.
    pub name: Option<&'static str>,
}

impl TypeOid {
    /// Looks `oid` up in the gemSpec_OID tables.
    pub fn new(oid: &ObjectIdentifier) -> Self {
        let info = ti_pki::oid::lookup(oid);
        TypeOid {
            oid: oid.to_string(),
            reference: info.map(|i| i.reference),
            name: info.map(|i| i.description).filter(|d| !d.is_empty()),
        }
    }
}
