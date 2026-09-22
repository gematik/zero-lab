//! The validator and its result. Validation runs chain building, path
//! validation, the gemSpec_Krypt key admissibility check and the revocation
//! check, and folds every finding into one result: whether the certificate is
//! valid, the errors with an [`ErrorCode`](crate::ErrorCode) each, the warnings,
//! and the built chain with each certificate's position.
