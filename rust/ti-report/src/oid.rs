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
