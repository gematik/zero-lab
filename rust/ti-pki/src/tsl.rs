//! The Trust Service Status List gematik publishes: the ETSI TS 119 612 XML
//! naming every CA and OCSP responder the TI currently sanctions. It supplies
//! the intermediate CAs that let a chain reach the anchors and the responders
//! allowed to answer for those CAs, but it is not a trust source. Its own
//! authenticity is checked through the detached `.sig` file against the
//! TSL-Signer-CA anchor, never through the inline XMLDSig.

/// Download point of the production TSL.
pub const URL_PROD: &str = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml";

/// Download point of the reference TSL, which the development environment shares.
pub const URL_REF: &str = "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml";

/// Download point of the test TSL.
pub const URL_TEST: &str = "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml";

/// What a verified TSL contributes to the loading layer.
#[cfg(feature = "load")]
pub(crate) struct VerifiedTsl {
    pub(crate) next_update: Option<crate::load::Timestamp>,
}

/// Verifies the TSL's detached signature against the TSL-Signer-CA anchor (which the
/// port adds to the configuration) and reads its `NextUpdate`.
#[cfg(feature = "load")]
pub(crate) fn verify_tsl(_tsl: &[u8]) -> Result<VerifiedTsl, crate::load::VerifyError> {
    todo!("gempki-port: TSL detached signature from go/gempki/tsl/signature.go")
}
