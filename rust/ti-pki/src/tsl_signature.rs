//! The signature of a TSL (`spec/tsl-xmldsig`, part A): `ti-xmldsig` checks the XML
//! against the fixed XMLDSig/XAdES profile and the reference digests; this module parses
//! the signer certificate, binds it by serial number, requires a brainpoolP256r1 key and
//! verifies the ECDSA value over the canonical `SignedInfo`.
//!
//! A verified signature proves only that the signer certificate's key signed the list.
//! Whether that certificate is the TSL signer is the next step (parts B and E: anchor,
//! validity, key usage, profile); until then nothing from the TSL may be used.

use core::fmt;

use bp256::BrainpoolP256r1;
use rustls_pki_types::alg_id;
use ti_xmldsig::{Document, ErrorKind, Limits};

use crate::Certificate;
use crate::algorithms::brainpool::BRAINPOOL_P256R1;
use crate::algorithms::{AlgorithmSet, find};

/// The result codes of `spec/tsl-xmldsig` this module produces: the message short names
/// of gemSpec_PKI Tab_PKI_274, in lower case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TslCode {
    /// The input is not well-formed XML within the limits (1011).
    TslNotWellformed,
    /// The signature does not match the profile or does not verify (1013).
    XmlSignatureError,
    /// `KeyInfo` does not hold exactly one parsable certificate (1002).
    TslCertExtractionError,
}

impl TslCode {
    /// The code's name, e.g. `xml_signature_error`.
    pub const fn as_str(self) -> &'static str {
        match self {
            TslCode::TslNotWellformed => "tsl_not_wellformed",
            TslCode::XmlSignatureError => "xml_signature_error",
            TslCode::TslCertExtractionError => "tsl_cert_extraction_error",
        }
    }

    /// The message number of Tab_PKI_274.
    pub const fn number(self) -> u16 {
        match self {
            TslCode::TslNotWellformed => 1011,
            TslCode::XmlSignatureError => 1013,
            TslCode::TslCertExtractionError => 1002,
        }
    }
}

impl fmt::Display for TslCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected TSL: the result code, the rule of `spec/tsl-xmldsig` that failed, and what
/// exactly failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {rule}: {detail}")]
pub struct TslError {
    /// The result code.
    pub code: TslCode,
    /// The rule, e.g. `TSLSIG-018`.
    pub rule: &'static str,
    /// What failed, for humans; not stable.
    pub detail: String,
}

impl TslError {
    fn signature(rule: &'static str, detail: impl Into<String>) -> Self {
        TslError {
            code: TslCode::XmlSignatureError,
            rule,
            detail: detail.into(),
        }
    }
}

impl From<ti_xmldsig::Error> for TslError {
    fn from(e: ti_xmldsig::Error) -> Self {
        let code = match e.kind() {
            ErrorKind::NotWellFormed => TslCode::TslNotWellformed,
            ErrorKind::SignerCertificate => TslCode::TslCertExtractionError,
            _ => TslCode::XmlSignatureError,
        };
        TslError {
            code,
            rule: e.rule(),
            detail: e.detail().to_owned(),
        }
    }
}

/// A TSL whose signature verifies under the key of its signer certificate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignedTsl {
    /// The certificate in `KeyInfo`, which `CertDigest` and `X509SerialNumber` bind. Not
    /// yet authenticated.
    pub signer: Certificate,
    /// The canonical bytes of the signed content (TSLSIG-023): what to parse the TSL
    /// from, never the received bytes.
    pub content: Vec<u8>,
    /// `SigningTime` as written; informational (TSLSIG-021).
    pub signing_time: String,
}

/// Verifies the signature of the TSL `xml` with the algorithms of `algorithms`
/// (TSLSIG-001, 010 – 023).
///
/// # Errors
///
/// [`TslError`] with the code and the rule of the first check that failed.
pub fn verify(xml: &[u8], algorithms: &AlgorithmSet) -> Result<SignedTsl, TslError> {
    let xml_checked = Document::parse(xml, &Limits::TSL)?.verify_tsl_signature()?;

    let signer = Certificate::from_der(&xml_checked.signer_certificate).map_err(|e| TslError {
        code: TslCode::TslCertExtractionError,
        rule: "TSLSIG-022",
        detail: format!("signer certificate: {e}"),
    })?;
    if !serial_matches(&xml_checked.signer_serial, signer.serial()) {
        return Err(TslError::signature(
            "TSLSIG-020",
            format!(
                "X509SerialNumber {} is not the signer certificate's serial number",
                xml_checked.signer_serial
            ),
        ));
    }
    if signer.public_key_alg_id() != BRAINPOOL_P256R1.as_ref() {
        return Err(TslError::signature(
            "TSLSIG-012",
            "the signer key is not on brainpoolP256r1",
        ));
    }

    // XMLDSig writes r ‖ s; the algorithms take the DER ECDSA-Sig-Value.
    let signature = ecdsa::Signature::<BrainpoolP256r1>::from_slice(&xml_checked.signature)
        .map_err(|_| TslError::signature("TSLSIG-018", "r or s is out of range"))?
        .to_der();
    let algorithm = find(
        algorithms,
        BRAINPOOL_P256R1.as_ref(),
        alg_id::ECDSA_SHA256.as_ref(),
    )
    .ok_or_else(|| {
        TslError::signature(
            "TSLSIG-012",
            "the algorithm set has no ECDSA brainpoolP256r1 SHA-256",
        )
    })?;
    algorithm
        .verify_signature(
            signer.public_key(),
            &xml_checked.signed_info,
            signature.as_bytes(),
        )
        .map_err(|_| TslError::signature("TSLSIG-018", "the signature value does not verify"))?;

    Ok(SignedTsl {
        signer,
        content: xml_checked.content,
        signing_time: xml_checked.signing_time,
    })
}

/// Whether the decimal `written` (`X509SerialNumber`, an `xsd:integer`) is the serial
/// number whose big-endian two's-complement bytes are `serial`.
fn serial_matches(written: &str, serial: &[u8]) -> bool {
    // A serial number has at most 20 octets (RFC 5280 §4.1.2.2), so at most 49 digits;
    // the limit keeps the conversion linear in practice. Negative serials do not occur
    // here: ti-xmldsig accepts digits only.
    if written.len() > 64 || serial.first().is_some_and(|b| b & 0x80 != 0) {
        return false;
    }
    let mut value: Vec<u8> = Vec::new();
    for digit in written.bytes() {
        if !digit.is_ascii_digit() {
            return false;
        }
        let mut carry = digit - b'0';
        for byte in value.iter_mut().rev() {
            let [high, low] = (u16::from(*byte) * 10 + u16::from(carry)).to_be_bytes();
            *byte = low;
            carry = high;
        }
        if carry != 0 {
            value.insert(0, carry);
        }
    }
    let significant =
        |bytes: &[u8]| -> Vec<u8> { bytes.iter().copied().skip_while(|b| *b == 0).collect() };
    significant(&value) == significant(serial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::DEFAULT;

    fn real(name: &str) -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-xmldsig/testdata/tsl/real/"
        );
        std::fs::read(format!("{path}{name}")).unwrap()
    }

    #[test]
    fn tslsig_018_published_tsls_verify() {
        for name in [
            "pu-10333.xml",
            "pu-10334.xml",
            "tu-10687.xml",
            "tu-10713.xml",
        ] {
            let signed = verify(&real(name), DEFAULT).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                signed.signer.subject_cn().starts_with("TSL Signing Unit"),
                "{name}"
            );
            assert!(signed.content.starts_with(b"<TrustServiceStatusList "));
        }
    }

    #[test]
    fn tslsig_018_bundled_tsl_verifies() {
        let xml = include_bytes!("../tests/fixtures/tsl/ECC-RSA_TSL.xml");
        verify(xml, DEFAULT).unwrap();
    }

    /// A TSL whose XML still matches the profile and whose digests still hold, but whose
    /// `SignedInfo` changed (the free `Id` value of reference 2), fails at the ECDSA check.
    #[test]
    fn tslsig_018_changed_signed_info_fails_the_signature() {
        let xml = String::from_utf8(real("pu-10334.xml")).unwrap();
        let changed = xml.replacen(
            "<ds:Reference Id=\"Reference-SignedProperties-",
            "<ds:Reference Id=\"Reference-SignedPropertieS-",
            1,
        );
        assert_ne!(changed, xml);
        let e = verify(changed.as_bytes(), DEFAULT).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::XmlSignatureError, "TSLSIG-018"),
            "{e}"
        );
    }

    #[test]
    fn tslsig_012_needs_brainpool_in_the_algorithm_set() {
        let e = verify(&real("pu-10334.xml"), crate::algorithms::STANDARD).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::XmlSignatureError, "TSLSIG-012"),
            "{e}"
        );
    }

    #[test]
    fn codes_of_the_xml_layer() {
        let e = verify(b"<a>", DEFAULT).unwrap_err();
        assert_eq!((e.code, e.rule), (TslCode::TslNotWellformed, "TSLSIG-001"));
        assert_eq!(e.code.number(), 1011);

        let xml = String::from_utf8(real("pu-10334.xml")).unwrap();
        let changed = xml.replacen(
            "</ds:X509Data>",
            "</ds:X509Data><ds:KeyName>k</ds:KeyName>",
            1,
        );
        let e = verify(changed.as_bytes(), DEFAULT).unwrap_err();
        assert_eq!(
            (e.code, e.rule),
            (TslCode::TslCertExtractionError, "TSLSIG-022"),
            "{e}"
        );
        assert_eq!(e.code.number(), 1002);
    }

    #[test]
    fn tslsig_020_serial_numbers() {
        assert!(serial_matches("6", &[0x06]));
        assert!(serial_matches("0006", &[0x06]));
        assert!(serial_matches("128", &[0x00, 0x80]));
        assert!(serial_matches("262", &[0x01, 0x06]));
        assert!(!serial_matches("6", &[0x01, 0x06]));
        assert!(!serial_matches("7", &[0x06]));
        assert!(!serial_matches("128", &[0x80]));
        let big = "1461501637330902918203684832716283019655932542975"; // 2^160 − 1
        assert!(serial_matches(
            big,
            &[[0x00].as_slice(), &[0xff; 20]].concat()
        ));
        assert!(!serial_matches(&"9".repeat(65), &[0x01]));
    }
}
