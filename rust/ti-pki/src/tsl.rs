//! The Trust Service Status List gematik publishes: the ETSI TS 119 612 XML
//! naming every CA and OCSP responder the TI currently sanctions. It supplies
//! the intermediate CAs that let a chain reach the anchors and the responders
//! allowed to answer for those CAs, but it is not a trust source. Its own
//! authenticity is checked through the detached `.sig` file against the
//! TSL-Signer-CA anchor, never through the inline XMLDSig.
