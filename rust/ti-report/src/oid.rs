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
