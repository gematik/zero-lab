//! The OCSP checker: queries a certificate's responder, from its AIA
//! extension or an override, and verifies the answer. A response is accepted
//! only if its CertID matches the certificate, its signer is an authorized
//! responder (the issuing CA, a delegate it certified, or a responder the TSL
//! lists for that CA) and it is fresh within a tight window. Failures are
//! reported as the codes the [`revocation`](crate::revocation) table decides on.
