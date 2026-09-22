//! Certificate types of gemSpec_PKI Tab_PKI_405 and their detection. Each
//! type carries the baseline every certificate of that type must satisfy
//! (key usage, extended key usage, certificate policies, role OIDs),
//! transcribed from gemSpec_PKI's profile tables; every value is a floor the
//! checks require, never an equality. Detection reads the type off a
//! certificate's policies and falls back to the admission extension.

/// A gemSpec_PKI Tab_PKI_405 certificate type. The variant docs give the
/// spec's name, which is what users see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertificateType {
    /// `C.CH.QES`
    ChQes,
    /// `C.CH.SIG`
    ChSig,
    /// `C.CH.ENC`
    ChEnc,
    /// `C.CH.ENCV`
    ChEncv,
    /// `C.CH.AUT`
    ChAut,
    /// `C.CH.AUTN`
    ChAutn,
    /// `C.HP.QES`
    HpQes,
    /// `C.HP.AUT`
    HpAut,
    /// `C.HP.ENC`
    HpEnc,
    /// `C.HCI.AUT`
    HciAut,
    /// `C.HCI.ENC`
    HciEnc,
    /// `C.HCI.OSIG`
    HciOsig,
    /// `C.FD.TLS-S`
    FdTlsS,
    /// `C.FD.TLS-C`
    FdTlsC,
    /// `C.FD.SIG`
    FdSig,
    /// `C.FD.ENC`
    FdEnc,
    /// `C.FD.AUT`
    FdAut,
    /// `C.FD.OSIG`
    FdOsig,
    /// `C.ZD.TLS-S`
    ZdTlsS,
    /// `C.ZD.SIG`
    ZdSig,
    /// `C.HSK.SIG`
    HskSig,
    /// `C.HSK.ENC`
    HskEnc,
    /// `C.GEM.VER`
    GemVer,
}
