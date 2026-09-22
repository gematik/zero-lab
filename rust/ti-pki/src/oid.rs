//! Object identifiers gemSpec_OID defines for the TI (Tab_PKI_401 to 406:
//! instances, professions, institutions, certificate policies, certificate
//! types and technical roles), each declared together with the spec's
//! reference name and description so the two cannot drift. A names table maps
//! an OID back to that name for display.

use const_oid::ObjectIdentifier;

/// The gematik arc every TI OID lives under unless it spells its own out.
pub const TI_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.276.0.76.4");

/// The ISIS-MTT Admission extension carrying gematik profession information
/// on SMC-B and HBA cards.
pub const ADMISSION_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.8.3.3");
