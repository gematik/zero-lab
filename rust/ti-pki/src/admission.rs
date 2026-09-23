//! The gematik admission extension (ISIS-MTT `AdmissionSyntax`, 1.3.36.8.3.3): the
//! profession or institution a card holder is admitted as, its OIDs and a registration
//! number.
//!
//! ```text
//! AdmissionSyntax ::= SEQUENCE {
//!   admissionAuthority GeneralName OPTIONAL,
//!   contentsOfAdmissions SEQUENCE OF Admissions }
//! Admissions ::= SEQUENCE {
//!   admissionAuthority [0] EXPLICIT GeneralName OPTIONAL,
//!   namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL,
//!   professionInfos SEQUENCE OF ProfessionInfo }
//! NamingAuthority ::= SEQUENCE {
//!   namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
//!   namingAuthorityUrl IA5String OPTIONAL,
//!   namingAuthorityText DirectoryString OPTIONAL }
//! ProfessionInfo ::= SEQUENCE {
//!   namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
//!   professionItems SEQUENCE OF DirectoryString,
//!   professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//!   registrationNumber PrintableString OPTIONAL,
//!   addProfessionInfo OCTET STRING OPTIONAL }
//! ```
//!
//! Like `gempki`, only the first profession info of the first admission is read; TI
//! certificates carry exactly one.

use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, OctetString, PrintableString};
use der::{Decode, Sequence};
use x509_cert::ext::pkix::name::{DirectoryString, GeneralName};

use crate::Error;

/// What an admission extension says about the certificate holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionStatement {
    /// The profession or institution in words, e.g. `Arztpraxis`.
    pub profession_items: Vec<String>,
    /// The profession or institution OIDs (Tab_PKI_402 / 403 / 406).
    pub profession_oids: Vec<ObjectIdentifier>,
    /// The registration number, e.g. a Telematik-ID.
    pub registration_number: Option<String>,
}

impl AdmissionStatement {
    /// Decodes the DER value of an admission extension.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] if the value is not an `AdmissionSyntax`, [`Error::Malformed`] if
    /// it holds no admission or no profession info.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let syntax = AdmissionSyntax::from_der(der)?;
        let admissions = syntax
            .contents_of_admissions
            .into_iter()
            .next()
            .ok_or_else(|| malformed("no contents of admissions"))?;
        let info = admissions
            .profession_infos
            .into_iter()
            .next()
            .ok_or_else(|| malformed("no profession infos"))?;
        Ok(AdmissionStatement {
            profession_items: info
                .profession_items
                .iter()
                .map(|item| item.value().into_owned())
                .collect(),
            profession_oids: info.profession_oids.unwrap_or_default(),
            registration_number: info.registration_number.map(|n| n.to_string()),
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
impl AdmissionStatement {
    /// The DER value of an admission extension carrying this statement; for building
    /// test certificates.
    ///
    /// # Panics
    ///
    /// If the registration number is not a valid PrintableString.
    pub fn to_der(&self) -> Vec<u8> {
        use der::Encode;
        let syntax = AdmissionSyntax {
            admission_authority: None,
            contents_of_admissions: vec![Admissions {
                admission_authority: None,
                naming_authority: None,
                profession_infos: vec![ProfessionInfo {
                    naming_authority: None,
                    profession_items: self
                        .profession_items
                        .iter()
                        .map(|item| DirectoryString::Utf8String(item.clone()))
                        .collect(),
                    profession_oids: Some(self.profession_oids.clone()),
                    registration_number: self
                        .registration_number
                        .as_ref()
                        .map(|n| PrintableString::new(n).expect("printable")),
                    add_profession_info: None,
                }],
            }],
        };
        syntax.to_der().expect("admission encodes")
    }
}

fn malformed(reason: &str) -> Error {
    Error::Malformed {
        what: "admission extension",
        reason: reason.to_owned(),
    }
}

#[derive(Sequence)]
#[allow(dead_code, reason = "decoded to match the ASN.1 structure, not read")]
struct AdmissionSyntax {
    #[asn1(optional = "true")]
    admission_authority: Option<GeneralName>,
    contents_of_admissions: Vec<Admissions>,
}

#[derive(Sequence)]
#[allow(dead_code, reason = "decoded to match the ASN.1 structure, not read")]
struct Admissions {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    admission_authority: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    naming_authority: Option<NamingAuthority>,
    profession_infos: Vec<ProfessionInfo>,
}

#[derive(Sequence)]
#[allow(dead_code, reason = "decoded to match the ASN.1 structure, not read")]
struct NamingAuthority {
    #[asn1(optional = "true")]
    id: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    url: Option<Ia5String>,
    #[asn1(optional = "true")]
    text: Option<DirectoryString>,
}

#[derive(Sequence)]
#[allow(dead_code, reason = "decoded to match the ASN.1 structure, not read")]
#[allow(
    clippy::struct_field_names,
    reason = "field names follow the ASN.1 module"
)]
struct ProfessionInfo {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    naming_authority: Option<NamingAuthority>,
    profession_items: Vec<DirectoryString>,
    #[asn1(optional = "true")]
    profession_oids: Option<Vec<ObjectIdentifier>>,
    #[asn1(optional = "true")]
    registration_number: Option<PrintableString>,
    #[asn1(optional = "true")]
    add_profession_info: Option<OctetString>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::{SMCB_CA51, fixture};

    #[test]
    fn real_admission_statements() {
        for (pem, registration_number, oid) in [
            (
                include_str!("../tests/fixtures/admission-1.pem"),
                "1-2-ARZTPRAXIS-BerndRosenstrauch01",
                crate::oid::INST_ARZTPRAXIS,
            ),
            (
                include_str!("../tests/fixtures/admission-2.pem"),
                "3-SMC-B-Testkarte--883110000153440",
                crate::oid::INST_OEFFENTLICHE_APO,
            ),
        ] {
            let statement = fixture(pem).admission().unwrap().unwrap();
            assert_eq!(
                statement.registration_number.as_deref(),
                Some(registration_number)
            );
            assert_eq!(statement.profession_oids, [oid]);
            assert!(!statement.profession_items.is_empty());
        }
    }

    #[test]
    fn no_extension_is_none() {
        assert_eq!(fixture(SMCB_CA51).admission().unwrap(), None);
    }

    #[test]
    fn round_trip_and_malformed() {
        let statement = AdmissionStatement {
            profession_items: vec!["Ärztin/Arzt".into()],
            profession_oids: vec![crate::oid::PROF_ARZT],
            registration_number: Some("1-HBA-Testkarte-883110000129068".into()),
        };
        assert_eq!(
            AdmissionStatement::from_der(&statement.to_der()).unwrap(),
            statement
        );
        assert!(matches!(
            AdmissionStatement::from_der(&[0x30, 0x02, 0x30, 0x00]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            AdmissionStatement::from_der(b"junk"),
            Err(Error::Der(_))
        ));
    }
}
