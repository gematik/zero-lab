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
