//! Path validation of a built chain per RFC 5280 §6, plus the end-entity
//! checks a profile requires. Every certificate must be within its validity
//! window; every CA must be marked as such, allow certificate signing and
//! respect its path-length constraint; each link's signature is verified
//! under its issuer's key, for ECDSA on Brainpool and NIST curves and for RSA.
