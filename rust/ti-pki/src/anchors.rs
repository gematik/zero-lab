//! The trust anchors compiled into the crate, one root certificate per
//! environment: GEM.RCA8 for prod, GEM.RCA7 TEST-ONLY for dev and ref,
//! GEM.RCA8 TEST-ONLY for test, plus the TSL-Signer-CA anchor that verifies
//! the TSL's detached signature. They are taken straight from gematik's
//! distribution; if gematik rotates one, the constant changes and the crate
//! is rebuilt, there is no runtime override.
