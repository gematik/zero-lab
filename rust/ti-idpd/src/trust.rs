//! Whether the IDP's certificates are to be trusted: a question for the TSL, which this
//! crate does not load. The flow hands each certificate the IDP uses to a
//! [`CertificateTrust`] and stops when it is refused.
//!
//! gemSpec_IDP_Dienst has the IDP sign its discovery document with `PrK_DISC_SIG` and
//! its challenges and tokens with `PrK_IDP_SIG`, both C.FD.SIG certificates with the
//! role `oid_idpd`, published as the discovery document's `x5c` and in the `x5c` of
//! the `PuK_IDP_SIG` JWK. `PuK_IDP_ENC` comes without a certificate: it is trusted
//! because the verified discovery document names its URI.

use core::fmt;

/// Which of the IDP's certificates is being checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdpCertificate {
    /// The discovery document's signer (`puk_disc_sig`).
    DiscoverySigner,
    /// The challenge and token signer (`puk_idp_sig`).
    TokenSigner,
}

impl IdpCertificate {
    /// The key's name at the IDP: `puk_disc_sig` or `puk_idp_sig`.
    pub const fn as_str(self) -> &'static str {
        match self {
            IdpCertificate::DiscoverySigner => "puk_disc_sig",
            IdpCertificate::TokenSigner => "puk_idp_sig",
        }
    }
}

impl fmt::Display for IdpCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a check concluded about a certificate it did not refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checked {
    /// Valid for an IDP-Dienst: chain to a trust anchor, role, revocation.
    Verified,
    /// Not checked; the flow carries [`crate::Warning::IdpCertificatesUnverified`].
    Unchecked,
}

/// Decides about the IDP's certificates.
pub trait CertificateTrust {
    /// Checks `certificate_der`, the IDP's `which` certificate; `chain_der` is the rest
    /// of the `x5c` it came with, issuer first (usually empty).
    ///
    /// # Errors
    ///
    /// Why the certificate is not to be trusted; the flow stops with
    /// [`crate::Error::Untrusted`].
    fn check(
        &self,
        which: IdpCertificate,
        certificate_der: &[u8],
        chain_der: &[Vec<u8>],
    ) -> Result<Checked, String>;
}

impl<T: CertificateTrust + ?Sized> CertificateTrust for &T {
    fn check(
        &self,
        which: IdpCertificate,
        certificate_der: &[u8],
        chain_der: &[Vec<u8>],
    ) -> Result<Checked, String> {
        (**self).check(which, certificate_der, chain_der)
    }
}

/// Trusts every certificate unchecked: the signatures still verify, the signer's
/// standing is not asked. For tests and for callers without trust material.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unverified;

impl CertificateTrust for Unverified {
    fn check(&self, _: IdpCertificate, _: &[u8], _: &[Vec<u8>]) -> Result<Checked, String> {
        Ok(Checked::Unchecked)
    }
}
