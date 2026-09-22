//! Chain construction: walks issuer references from the leaf through the
//! supplied intermediates until it lands on a trust-store root, preferring
//! AuthorityKeyIdentifier matches over issuer-name matches so it works across
//! root rollovers. This is topology only; signatures and validity are the
//! concern of [`path`](crate::path). Length and cycles are bounded, so an
//! adversarial set of intermediates cannot make it run away.
