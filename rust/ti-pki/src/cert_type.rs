//! Certificate types of gemSpec_PKI Tab_PKI_405 and their detection. Each
//! type carries the baseline every certificate of that type must satisfy
//! (key usage, extended key usage, certificate policies, role OIDs),
//! transcribed from gemSpec_PKI's profile tables; every value is a floor the
//! checks require, never an equality. Detection reads the type off a
//! certificate's policies and falls back to the admission extension.

use core::fmt;
use core::str::FromStr;

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

use crate::Certificate;
use crate::oid;

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

impl CertificateType {
    /// Every type, in Tab_PKI_405 order.
    pub const ALL: [CertificateType; 23] = [
        CertificateType::ChQes,
        CertificateType::ChSig,
        CertificateType::ChEnc,
        CertificateType::ChEncv,
        CertificateType::ChAut,
        CertificateType::ChAutn,
        CertificateType::HpQes,
        CertificateType::HpAut,
        CertificateType::HpEnc,
        CertificateType::HciAut,
        CertificateType::HciEnc,
        CertificateType::HciOsig,
        CertificateType::FdTlsS,
        CertificateType::FdTlsC,
        CertificateType::FdSig,
        CertificateType::FdEnc,
        CertificateType::FdAut,
        CertificateType::FdOsig,
        CertificateType::ZdTlsS,
        CertificateType::ZdSig,
        CertificateType::HskSig,
        CertificateType::HskEnc,
        CertificateType::GemVer,
    ];

    /// The gemSpec_PKI name, e.g. `C.HCI.AUT`.
    pub const fn as_str(self) -> &'static str {
        self.entry().0
    }

    /// The Tab_PKI_405 object identifier.
    pub const fn oid(self) -> ObjectIdentifier {
        self.entry().1
    }

    /// The gemSpec_PKI baseline every certificate of this type must satisfy.
    pub const fn spec(self) -> &'static TypeSpec {
        self.entry().2
    }

    /// The type whose Tab_PKI_405 OID is `oid`.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<CertificateType> {
        Self::ALL.into_iter().find(|t| t.oid() == *oid)
    }

    const fn entry(self) -> (&'static str, ObjectIdentifier, &'static TypeSpec) {
        match self {
            CertificateType::ChQes => ("C.CH.QES", oid::CERT_TYPE_EGK_QES, &CH_QES),
            CertificateType::ChSig => ("C.CH.SIG", oid::CERT_TYPE_EGK_SIG, &CH_SIG),
            CertificateType::ChEnc => ("C.CH.ENC", oid::CERT_TYPE_EGK_ENC, &CH_ENC),
            CertificateType::ChEncv => ("C.CH.ENCV", oid::CERT_TYPE_EGK_ENCV, &CH_ENCV),
            CertificateType::ChAut => ("C.CH.AUT", oid::CERT_TYPE_EGK_AUT, &CH_AUT),
            CertificateType::ChAutn => ("C.CH.AUTN", oid::CERT_TYPE_EGK_AUTN, &CH_AUTN),
            CertificateType::HpQes => ("C.HP.QES", oid::CERT_TYPE_HBA_QES, &HP_QES),
            CertificateType::HpAut => ("C.HP.AUT", oid::CERT_TYPE_HBA_AUT, &HP_AUT),
            CertificateType::HpEnc => ("C.HP.ENC", oid::CERT_TYPE_HBA_ENC, &HP_ENC),
            CertificateType::HciAut => ("C.HCI.AUT", oid::CERT_TYPE_SMC_B_AUT, &HCI_AUT),
            CertificateType::HciEnc => ("C.HCI.ENC", oid::CERT_TYPE_SMC_B_ENC, &HCI_ENC),
            CertificateType::HciOsig => ("C.HCI.OSIG", oid::CERT_TYPE_SMC_B_OSIG, &HCI_OSIG),
            CertificateType::FdTlsS => ("C.FD.TLS-S", oid::CERT_TYPE_FD_TLS_S, &FD_TLS_S),
            CertificateType::FdTlsC => ("C.FD.TLS-C", oid::CERT_TYPE_FD_TLS_C, &FD_TLS_C),
            CertificateType::FdSig => ("C.FD.SIG", oid::CERT_TYPE_FD_SIG, &FD_SIG),
            CertificateType::FdEnc => ("C.FD.ENC", oid::CERT_TYPE_FD_ENC, &FD_ENC),
            CertificateType::FdAut => ("C.FD.AUT", oid::CERT_TYPE_FD_AUT, &FD_AUT),
            CertificateType::FdOsig => ("C.FD.OSIG", oid::CERT_TYPE_FD_OSIG, &FD_OSIG),
            CertificateType::ZdTlsS => ("C.ZD.TLS-S", oid::CERT_TYPE_ZD_TLS_S, &ZD_TLS_S),
            CertificateType::ZdSig => ("C.ZD.SIG", oid::CERT_TYPE_ZD_SIG, &ZD_SIG),
            CertificateType::HskSig => ("C.HSK.SIG", oid::CERT_TYPE_HSK_SIG, &HSK_SIG),
            CertificateType::HskEnc => ("C.HSK.ENC", oid::CERT_TYPE_HSK_ENC, &HSK_ENC),
            CertificateType::GemVer => ("C.GEM.VER", oid::CERT_TYPE_GEM_VER, &GEM_VER),
        }
    }
}

impl fmt::Display for CertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The input to [`CertificateType::from_str`] names no Tab_PKI_405 type.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown certificate type {0:?}")]
pub struct UnknownCertificateType(pub String);

impl FromStr for CertificateType {
    type Err = UnknownCertificateType;

    /// Parses the gemSpec_PKI name, e.g. `C.HCI.AUT`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| UnknownCertificateType(s.to_owned()))
    }
}

/// The gemSpec_PKI baseline of a certificate type. Every entry is a floor: the key
/// usage bits must all be set, one of the extended key usages must be present, every
/// policy must be asserted, one of the roles must be in the admission extension. An
/// empty entry means no requirement at this layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeSpec {
    /// Key usage bits that must all be set.
    pub key_usage: &'static [KeyUsages],
    /// Extended key usages of which one must be present.
    pub ext_key_usage: &'static [ObjectIdentifier],
    /// Certificate policies that must all be asserted.
    pub policies: &'static [ObjectIdentifier],
    /// Admission roles of which one must be present.
    pub role_oids: &'static [ObjectIdentifier],
}

/// `id-kp-serverAuth`.
pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// `id-kp-clientAuth`.
pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
/// `id-kp-emailProtection`.
pub const EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

const CC: &[KeyUsages] = &[KeyUsages::NonRepudiation];
const DS: &[KeyUsages] = &[KeyUsages::DigitalSignature];
const KA: &[KeyUsages] = &[KeyUsages::KeyAgreement];
const EGK_INSURANT: &[ObjectIdentifier] = &[oid::PROF_VERSICHERTER];
const HSK_ROLE: &[ObjectIdentifier] = &[oid::TECH_ROLE_HSK];

const fn spec(
    key_usage: &'static [KeyUsages],
    ext_key_usage: &'static [ObjectIdentifier],
    policies: &'static [ObjectIdentifier],
    role_oids: &'static [ObjectIdentifier],
) -> TypeSpec {
    TypeSpec {
        key_usage,
        ext_key_usage,
        policies,
        role_oids,
    }
}

// The X.509 profile tables of gemSpec_PKI (Tab_PKI_232–300, one per type), ECDSA branch
// — the TI issues no RSA cards any more, and the RSA baseline (keyEncipherment beside
// digitalSignature for AUT) would not fit the "every bit must be set" reading. Optional
// entries (C.CH.AUT's clientAuth, TSP-specific policies, the ETSI QSCD policy on
// C.HP.QES) are left out. Role lists are the whole spec tables — every Tab_PKI_403
// institution holds an SMC-B, every Tab_PKI_402 profession an HBA — so detection and
// validation cannot disagree. Fachdienst types carry no baseline role: the technical
// role is what a profile discriminates on.

// eGK, Tab_PKI_232–236, 297: gematik's umbrella policy plus the type. C.CH.AUT may carry
// clientAuth; C.CH.AUTN, the pseudonymous credential, must.
const CH_QES: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_QES],
    EGK_INSURANT,
);
const CH_SIG: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_SIG],
    EGK_INSURANT,
);
const CH_ENC: TypeSpec = spec(
    KA,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_ENC],
    EGK_INSURANT,
);
const CH_ENCV: TypeSpec = spec(
    KA,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_ENCV],
    EGK_INSURANT,
);
const CH_AUT: TypeSpec = spec(
    DS,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_AUT],
    EGK_INSURANT,
);
const CH_AUTN: TypeSpec = spec(
    DS,
    &[CLIENT_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_EGK_AUTN],
    EGK_INSURANT,
);

// HBA, Tab_PKI_268–270: the HBA policy, not gematik's umbrella one.
const HP_QES: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_HBA_CP, oid::CERT_TYPE_HBA_QES],
    oid::PROFESSIONS,
);
const HP_AUT: TypeSpec = spec(
    &[KeyUsages::DigitalSignature, KeyUsages::KeyAgreement],
    &[CLIENT_AUTH, EMAIL_PROTECTION],
    &[oid::POLICY_HBA_CP, oid::CERT_TYPE_HBA_AUT],
    oid::PROFESSIONS,
);
const HP_ENC: TypeSpec = spec(
    KA,
    &[],
    &[oid::POLICY_HBA_CP, oid::CERT_TYPE_HBA_ENC],
    oid::PROFESSIONS,
);

// SMC-B, Tab_PKI_238–240.
const HCI_AUT: TypeSpec = spec(
    DS,
    &[CLIENT_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_SMC_B_AUT],
    oid::INSTITUTIONS,
);
const HCI_ENC: TypeSpec = spec(
    KA,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_SMC_B_ENC],
    oid::INSTITUTIONS,
);
const HCI_OSIG: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_SMC_B_OSIG],
    oid::INSTITUTIONS,
);

// Fachdienst, Tab_PKI_241–246.
const FD_AUT: TypeSpec = spec(
    DS,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_AUT],
    &[],
);
const FD_SIG: TypeSpec = spec(
    DS,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_SIG],
    &[],
);
const FD_ENC: TypeSpec = spec(
    KA,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_ENC],
    &[],
);
const FD_OSIG: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_OSIG],
    &[],
);
const FD_TLS_S: TypeSpec = spec(
    DS,
    &[SERVER_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_TLS_S],
    &[],
);
const FD_TLS_C: TypeSpec = spec(
    DS,
    &[CLIENT_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_FD_TLS_C],
    &[],
);

// Zentrale Dienste, Tab_PKI_247, 296.
const ZD_TLS_S: TypeSpec = spec(
    DS,
    &[SERVER_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_ZD_TLS_S],
    &[],
);
const ZD_SIG: TypeSpec = spec(
    CC,
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_ZD_SIG],
    &[],
);

// Highspeed-Konnektor, Tab_PKI_284/285, and gematik's verification certificate
// (Tab_PKI_300), which asserts no key usage at all.
const HSK_SIG: TypeSpec = spec(
    CC,
    &[CLIENT_AUTH, SERVER_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_HSK_SIG],
    HSK_ROLE,
);
const HSK_ENC: TypeSpec = spec(
    KA,
    &[CLIENT_AUTH, SERVER_AUTH],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_HSK_ENC],
    HSK_ROLE,
);
const GEM_VER: TypeSpec = spec(
    &[],
    &[],
    &[oid::POLICY_GEM_OR_CP, oid::CERT_TYPE_GEM_VER],
    &[],
);

/// Classifies `cert` as a Tab_PKI_405 type; `None` if it carries no recognisable marker.
///
/// 1. The type OID in the certificate policies, where gemSpec_PKI puts it next to the
///    umbrella policy; this covers virtually every TI certificate.
/// 2. Otherwise, for issuers that leave the type OID out, the admission extension and
///    the key usage: an HBA profession, an SMC-B institution or the eGK insurant role,
///    with contentCommitment (QES/OSIG) taking precedence over digitalSignature (AUT)
///    over keyEncipherment/keyAgreement (ENC). An eGK's AUT and ENC certificates have
///    pseudonymous siblings (C.CH.AUTN, C.CH.ENCV) with the same admission and key
///    usage, so those are undecidable here and yield `None`.
pub fn detect_certificate_type(cert: &Certificate) -> Option<CertificateType> {
    cert.policies()
        .iter()
        .find_map(CertificateType::from_oid)
        .or_else(|| from_admission(cert))
}

fn from_admission(cert: &Certificate) -> Option<CertificateType> {
    let admission = cert.admission().ok().flatten()?;
    let family = admission.profession_oids.iter().find_map(|role| {
        if *role == oid::PROF_VERSICHERTER {
            Some(Family::Egk)
        } else if oid::INSTITUTIONS.contains(role) {
            Some(Family::SmcB)
        } else if oid::PROFESSIONS.contains(role) {
            Some(Family::Hba)
        } else {
            None
        }
    })?;
    let usage = cert.key_usage().map(|ku| ku.0).unwrap_or_default();
    let class = if usage.contains(KeyUsages::NonRepudiation) {
        Usage::Qes
    } else if usage.contains(KeyUsages::DigitalSignature) {
        Usage::Aut
    } else if usage.contains(KeyUsages::KeyEncipherment) || usage.contains(KeyUsages::KeyAgreement)
    {
        Usage::Enc
    } else {
        return None;
    };
    match (family, class) {
        (Family::Hba, Usage::Qes) => Some(CertificateType::HpQes),
        (Family::Hba, Usage::Aut) => Some(CertificateType::HpAut),
        (Family::Hba, Usage::Enc) => Some(CertificateType::HpEnc),
        (Family::SmcB, Usage::Qes) => Some(CertificateType::HciOsig),
        (Family::SmcB, Usage::Aut) => Some(CertificateType::HciAut),
        (Family::SmcB, Usage::Enc) => Some(CertificateType::HciEnc),
        (Family::Egk, Usage::Qes) => Some(CertificateType::ChQes),
        (Family::Egk, _) => None,
    }
}

#[derive(Clone, Copy)]
enum Family {
    Hba,
    SmcB,
    Egk,
}

#[derive(Clone, Copy)]
enum Usage {
    Qes,
    Aut,
    Enc,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEM: ObjectIdentifier = oid::POLICY_GEM_OR_CP;
    const HBA: ObjectIdentifier = oid::POLICY_HBA_CP;

    /// gemSpec_PKI's baselines transcribed a second time, independently of the table
    /// above: key usage, extended key usage, policies, roles.
    #[test]
    fn baselines_match_gemspec_pki() {
        use CertificateType as T;
        type Row<'a> = (
            T,
            &'a [KeyUsages],
            &'a [ObjectIdentifier],
            [ObjectIdentifier; 2],
            &'a [ObjectIdentifier],
        );
        use KeyUsages::{DigitalSignature as Ds, KeyAgreement as Ka, NonRepudiation as Cc};
        let (client, server, mail) = (CLIENT_AUTH, SERVER_AUTH, EMAIL_PROTECTION);
        let egk: &[ObjectIdentifier] = &[oid::PROF_VERSICHERTER];
        let hsk: &[ObjectIdentifier] = &[oid::TECH_ROLE_HSK];
        let (hba_roles, smcb_roles) = (oid::PROFESSIONS, oid::INSTITUTIONS);
        #[rustfmt::skip]
        let table: [Row<'_>; 23] = [
            (T::ChQes, &[Cc], &[], [GEM, oid::CERT_TYPE_EGK_QES], egk),
            (T::ChSig, &[Cc], &[], [GEM, oid::CERT_TYPE_EGK_SIG], egk),
            (T::ChEnc, &[Ka], &[], [GEM, oid::CERT_TYPE_EGK_ENC], egk),
            (T::ChEncv, &[Ka], &[], [GEM, oid::CERT_TYPE_EGK_ENCV], egk),
            (T::ChAut, &[Ds], &[], [GEM, oid::CERT_TYPE_EGK_AUT], egk),
            (T::ChAutn, &[Ds], &[client], [GEM, oid::CERT_TYPE_EGK_AUTN], egk),
            (T::HpQes, &[Cc], &[], [HBA, oid::CERT_TYPE_HBA_QES], hba_roles),
            (T::HpAut, &[Ds, Ka], &[client, mail], [HBA, oid::CERT_TYPE_HBA_AUT], hba_roles),
            (T::HpEnc, &[Ka], &[], [HBA, oid::CERT_TYPE_HBA_ENC], hba_roles),
            (T::HciAut, &[Ds], &[client], [GEM, oid::CERT_TYPE_SMC_B_AUT], smcb_roles),
            (T::HciEnc, &[Ka], &[], [GEM, oid::CERT_TYPE_SMC_B_ENC], smcb_roles),
            (T::HciOsig, &[Cc], &[], [GEM, oid::CERT_TYPE_SMC_B_OSIG], smcb_roles),
            (T::FdTlsS, &[Ds], &[server], [GEM, oid::CERT_TYPE_FD_TLS_S], &[]),
            (T::FdTlsC, &[Ds], &[client], [GEM, oid::CERT_TYPE_FD_TLS_C], &[]),
            (T::FdSig, &[Ds], &[], [GEM, oid::CERT_TYPE_FD_SIG], &[]),
            (T::FdEnc, &[Ka], &[], [GEM, oid::CERT_TYPE_FD_ENC], &[]),
            (T::FdAut, &[Ds], &[], [GEM, oid::CERT_TYPE_FD_AUT], &[]),
            (T::FdOsig, &[Cc], &[], [GEM, oid::CERT_TYPE_FD_OSIG], &[]),
            (T::ZdTlsS, &[Ds], &[server], [GEM, oid::CERT_TYPE_ZD_TLS_S], &[]),
            (T::ZdSig, &[Cc], &[], [GEM, oid::CERT_TYPE_ZD_SIG], &[]),
            (T::HskSig, &[Cc], &[client, server], [GEM, oid::CERT_TYPE_HSK_SIG], hsk),
            (T::HskEnc, &[Ka], &[client, server], [GEM, oid::CERT_TYPE_HSK_ENC], hsk),
            (T::GemVer, &[], &[], [GEM, oid::CERT_TYPE_GEM_VER], &[]),
        ];
        for (t, key_usage, ext_key_usage, policies, roles) in table {
            let spec = t.spec();
            assert_eq!(spec.key_usage, key_usage, "{t}");
            assert_eq!(spec.ext_key_usage, ext_key_usage, "{t}");
            assert_eq!(spec.policies, policies, "{t}");
            assert_eq!(spec.role_oids, roles, "{t}");
            assert_eq!(t.oid(), policies[1], "{t}");
        }
        assert_eq!(CertificateType::ALL.len(), table.len());
    }

    #[test]
    fn names_oids_and_parsing() {
        for t in CertificateType::ALL {
            assert_eq!(t.as_str().parse::<CertificateType>(), Ok(t));
            assert_eq!(CertificateType::from_oid(&t.oid()), Some(t));
            assert_eq!(t.to_string(), t.as_str());
        }
        assert_eq!(CertificateType::HciAut.as_str(), "C.HCI.AUT");
        assert!("C.NOPE".parse::<CertificateType>().is_err());
        assert_eq!(CertificateType::from_oid(&oid::POLICY_GEM_OR_CP), None);
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn a_certificate_built_to_its_baseline_is_detected_and_passes() {
        use crate::checks;
        use crate::testing::typed;
        for t in CertificateType::ALL {
            let name = format!(
                "type-{}",
                t.as_str()[2..].to_ascii_lowercase().replace('.', "-")
            );
            let cert = typed(&name);
            assert_eq!(detect_certificate_type(&cert), Some(t), "{name}");
            let spec = t.spec();
            checks::key_usage(spec.key_usage)(&cert).unwrap();
            if !spec.ext_key_usage.is_empty() {
                checks::any_ext_key_usage(spec.ext_key_usage)(&cert).unwrap();
            }
            checks::certificate_policies(spec.policies)(&cert).unwrap();
            checks::role_oid(spec.role_oids)(&cert).unwrap();
        }
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn every_role_of_the_spec_tables_counts() {
        use crate::testing::typed;
        for (name, t) in [
            ("role-hci-aut-kostentraeger", CertificateType::HciAut),
            ("role-hci-aut-kim-anbieter", CertificateType::HciAut),
            ("role-hp-qes-hebamme", CertificateType::HpQes),
            ("role-hp-qes-notfallsanitaeter", CertificateType::HpQes),
        ] {
            let cert = typed(name);
            assert_eq!(detect_certificate_type(&cert), Some(t), "{name}");
            crate::checks::role_oid(t.spec().role_oids)(&cert).unwrap();
        }
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn admission_fallback() {
        use crate::testing::typed;
        for (name, want) in [
            (
                "fallback-hci-aut-krankenhaus",
                Some(CertificateType::HciAut),
            ),
            ("fallback-hci-enc-apotheke", Some(CertificateType::HciEnc)),
            ("fallback-hci-osig-praxis", Some(CertificateType::HciOsig)),
            ("fallback-hp-qes-arzt", Some(CertificateType::HpQes)),
            ("fallback-hp-aut-apotheker", Some(CertificateType::HpAut)),
            ("fallback-hp-enc-zahnarzt", Some(CertificateType::HpEnc)),
            ("fallback-ch-qes", Some(CertificateType::ChQes)),
            ("fallback-ch-aut-undecidable", None),
            ("fallback-ch-enc-undecidable", None),
            ("none-umbrella-only", None),
            ("none-unrelated-admission", None),
        ] {
            assert_eq!(detect_certificate_type(&typed(name)), want, "{name}");
        }
    }
}
