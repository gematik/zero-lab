//! Named validation profiles for the common TI use cases (smb-aut, idp-sig,
//! epa-vau-aut, zeta-guard-aut) and their selection. A profile states the
//! certificate types it accepts, its revocation strictness and optionally the
//! admission role that identifies it. Automatic selection prefers a profile
//! matched on its role over one that merely owns the type, and reports an
//! ambiguous or unclaimed certificate as such rather than guessing.
//!
//! A [`CertificateType`] carries the spec-mandated baseline (key usage, extended key
//! usage, policies, roles); a profile is the use-case overlay on top.
//! [`Profile::validator`] composes the two.

use core::fmt;
use std::sync::Arc;

use const_oid::ObjectIdentifier;

use crate::cert_type::{CertificateType, detect_certificate_type};
use crate::revocation::RevocationMode;
use crate::validate::Validator;
use crate::{Certificate, TrustConfig, TrustStore, oid};

/// A named, type-aware validation strategy.
#[derive(Debug)]
pub struct Profile {
    /// Kebab-case slug, e.g. `smb-aut`.
    pub name: &'static str,
    /// One-line summary for listings.
    pub description: &'static str,
    /// The revocation strictness the use case asks for; see [`Profile::validator`] for
    /// how it combines with the configuration.
    pub revocation: RevocationMode,
    /// Certificate policies the profile requires on top of the type baseline.
    pub extra_policies: &'static [ObjectIdentifier],
    /// When non-empty, replaces the type baseline's roles: the end entity must assert
    /// one of these. Replacing rather than adding is deliberate, as the check is
    /// any-of and adding would widen the accepted set; a profile narrows a type.
    ///
    /// It doubles as the selection discriminator: a profile with roles is only
    /// selected automatically for a certificate asserting one of them.
    pub required_role_oids: &'static [ObjectIdentifier],
    /// The types the profile is meant for. A certificate of another type may still
    /// be validated under it, deliberately, with a warning from the caller.
    pub accepts_types: &'static [CertificateType],
    /// The types for which the profile is the automatic default. A type is in the
    /// defaults of at most one profile.
    pub default_for: &'static [CertificateType],
}

/// SMC-B-family institution authentication (C.HCI.AUT). SMB is the umbrella for every
/// SMC-B variant (SMC-B, HSM-B, SMC-B-ORG). SoftFail, so an OCSP outage does not
/// reject an SMC-B login where the configuration allows it.
pub static SMB_AUT: Profile = Profile {
    name: "smb-aut",
    description: "SMC-B institution authentication (SMB = SMC-B / HSM-B / SMC-B-ORG)",
    revocation: RevocationMode::SoftFail,
    extra_policies: &[],
    required_role_oids: &[],
    accepts_types: &[CertificateType::HciAut],
    default_for: &[CertificateType::HciAut],
};

/// The C.FD.AUT certificate an ePA Aktensystem VAU presents for authenticity. Told
/// apart from other C.FD.AUT certificates by its role, oid_epa_vau, which also appears
/// on the VAU's ENC and SIG certificates, hence the type in the name. No default: a
/// C.FD.AUT without a known role is something else again.
pub static EPA_VAU_AUT: Profile = Profile {
    name: "epa-vau-aut",
    description: "ePA Aktensystem VAU backend authenticity",
    revocation: RevocationMode::HardFail,
    extra_policies: &[],
    required_role_oids: &[oid::TECH_ROLE_EPA_VAU],
    accepts_types: &[CertificateType::FdAut],
    default_for: &[],
};

/// The C.FD.SIG certificates an IDP signs its discovery document and tokens with,
/// identified by oid_idpd. There is deliberately no idp-aut: an IDP publishes no
/// C.FD.AUT.
pub static IDP_SIG: Profile = Profile {
    name: "idp-sig",
    description: "IDP discovery document and token signing",
    revocation: RevocationMode::HardFail,
    extra_policies: &[],
    required_role_oids: &[oid::TECH_ROLE_IDPD],
    accepts_types: &[CertificateType::FdSig],
    default_for: &[],
};

/// The C.FD.AUT certificate a ZETA Guard access service layer presents, identified by
/// oid_zeta-guard like [`EPA_VAU_AUT`] by its own role.
pub static ZETA_GUARD_AUT: Profile = Profile {
    name: "zeta-guard-aut",
    description: "ZETA Guard access service layer authenticity",
    revocation: RevocationMode::HardFail,
    extra_policies: &[],
    required_role_oids: &[oid::TECH_ROLE_ZETA_GUARD],
    accepts_types: &[CertificateType::FdAut],
    default_for: &[],
};

/// Every profile, sorted by name.
pub static PROFILES: &[&Profile] = &[&EPA_VAU_AUT, &IDP_SIG, &SMB_AUT, &ZETA_GUARD_AUT];

/// Selector value for automatic selection ([`select_for_cert`]).
pub const AUTO: &str = "auto";

/// Selector value for chain-only validation, without end-entity requirements.
pub const NONE: &str = "none";

/// Every legal profile selector: [`AUTO`], [`NONE`] and the profile names. Build help
/// and error texts from this rather than repeating the list.
pub fn selector_values() -> Vec<&'static str> {
    [AUTO, NONE]
        .into_iter()
        .chain(PROFILES.iter().map(|p| p.name))
        .collect()
}

/// The profile named `name`, case-insensitively. [`AUTO`], [`NONE`] and unknown names
/// are `None`; callers compare against those first.
pub fn lookup(name: &str) -> Option<&'static Profile> {
    PROFILES
        .iter()
        .copied()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

impl Profile {
    /// A validator for certificates of type `t`: `config`'s settings, the type's
    /// baseline, this profile's policies and roles on top, and
    /// [`revocation_mode`](Self::revocation_mode).
    pub fn validator(
        &self,
        config: &TrustConfig,
        store: Arc<TrustStore>,
        t: CertificateType,
    ) -> Validator {
        let mut validator = Validator::new(config, store).with_type_baseline(t);
        validator
            .required_policies
            .extend_from_slice(self.extra_policies);
        validator.required_role_oids = self.effective_role_oids(t).to_vec();
        validator.revocation = self.revocation_mode(config);
        validator
    }

    /// The revocation mode under `config`: the configuration's unless the profile is
    /// stricter. A profile can tighten what the operator configured (HardFail over
    /// SoftFail) but never loosen it, so a production configuration stays HardFail. A
    /// configuration with revocation disabled (non-production only) stays disabled.
    pub fn revocation_mode(&self, config: &TrustConfig) -> RevocationMode {
        let strictness = |mode| match mode {
            RevocationMode::Disabled => 0,
            RevocationMode::SoftFail => 1,
            RevocationMode::HardFail => 2,
        };
        if config.revocation == RevocationMode::Disabled
            || strictness(config.revocation) >= strictness(self.revocation)
        {
            config.revocation
        } else {
            self.revocation
        }
    }

    /// The roles this profile enforces for `t`: its own if it declares any, otherwise
    /// the type baseline's.
    pub fn effective_role_oids(&self, t: CertificateType) -> &'static [ObjectIdentifier] {
        if self.required_role_oids.is_empty() {
            t.spec().role_oids
        } else {
            self.required_role_oids
        }
    }

    /// Whether `t` is among the types the profile is meant for.
    pub fn accepts(&self, t: CertificateType) -> bool {
        self.accepts_types.contains(&t)
    }

    /// Whether `cert` asserts one of the profile's roles, or the profile declares none.
    ///
    /// Selection, not validation: the answer comes from unauthenticated certificate
    /// content and only says which profile is the right lens.
    pub fn matches(&self, cert: &Certificate) -> bool {
        if self.required_role_oids.is_empty() {
            return true;
        }
        cert.admission().ok().flatten().is_some_and(|admission| {
            admission
                .profession_oids
                .iter()
                .any(|role| self.required_role_oids.contains(role))
        })
    }

    /// How many discriminators the profile declares; one matched on a role outranks
    /// one that matched on nothing.
    fn specificity(&self) -> u8 {
        u8::from(!self.required_role_oids.is_empty())
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// How [`select_for_cert`] reached its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelectReason {
    /// The certificate asserts the profile's role.
    ByCert,
    /// The profile owns the certificate's type ([`Profile::default_for`]).
    ByDefault,
    /// Several profiles apply and none is more specific; the caller must ask.
    Ambiguous,
    /// No profile applies: none accepts the type, or those that do all require a role
    /// the certificate does not assert.
    Unclaimed,
}

impl SelectReason {
    /// `cert`, `default`, `ambiguous` or `none`, as in `gempki`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SelectReason::ByCert => "cert",
            SelectReason::ByDefault => "default",
            SelectReason::Ambiguous => "ambiguous",
            SelectReason::Unclaimed => "none",
        }
    }
}

impl fmt::Display for SelectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of [`select_for_cert`].
#[derive(Clone, Debug)]
pub struct ProfileSelection {
    /// What [`detect_certificate_type`] made of the certificate.
    pub cert_type: Option<CertificateType>,
    /// The selected profile, with [`SelectReason::ByCert`] or
    /// [`SelectReason::ByDefault`].
    pub profile: Option<&'static Profile>,
    /// The profiles the user could name when the selection is ambiguous, or the ones
    /// whose roles an unclaimed certificate lacks.
    pub candidates: Vec<&'static Profile>,
    /// How the answer was reached.
    pub reason: SelectReason,
    /// The deciding evidence in words, e.g. `asserts role 1.2.276.0.76.4.328 (ZETA
    /// Guard)`.
    pub detail: String,
}

/// The profiles that accept type `t`, in name order.
pub fn profiles_for_type(t: CertificateType) -> Vec<&'static Profile> {
    for_type(PROFILES, t)
}

/// The profile that owns `t` by default, if any.
pub fn default_profile_for(t: CertificateType) -> Option<&'static Profile> {
    default_for(PROFILES, t)
}

/// The profiles that accept `cert`'s type and whose roles it asserts, most specific
/// first, then by name.
pub fn profiles_for_cert(cert: &Certificate) -> Vec<&'static Profile> {
    for_cert(PROFILES, cert, detect_certificate_type(cert))
}

/// Picks the profile to validate `cert` under: the whole of what "auto" means, so
/// every caller resolves it the same way. A profile matched on its role outranks one
/// that owns the type by default; ambiguity is reported, never guessed.
pub fn select_for_cert(cert: &Certificate) -> ProfileSelection {
    select_from(PROFILES, cert)
}

fn for_type(registry: &[&'static Profile], t: CertificateType) -> Vec<&'static Profile> {
    registry.iter().copied().filter(|p| p.accepts(t)).collect()
}

fn default_for(registry: &[&'static Profile], t: CertificateType) -> Option<&'static Profile> {
    registry
        .iter()
        .copied()
        .find(|p| p.default_for.contains(&t))
}

fn for_cert(
    registry: &[&'static Profile],
    cert: &Certificate,
    t: Option<CertificateType>,
) -> Vec<&'static Profile> {
    let Some(t) = t else {
        return Vec::new();
    };
    let mut matched: Vec<&'static Profile> = for_type(registry, t)
        .into_iter()
        .filter(|p| p.matches(cert))
        .collect();
    matched.sort_by(|a, b| {
        b.specificity()
            .cmp(&a.specificity())
            .then(a.name.cmp(b.name))
    });
    matched
}

fn names(profiles: &[&Profile]) -> String {
    profiles
        .iter()
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn select_from(registry: &[&'static Profile], cert: &Certificate) -> ProfileSelection {
    let cert_type = detect_certificate_type(cert);
    let mut selection = ProfileSelection {
        cert_type,
        profile: None,
        candidates: Vec::new(),
        reason: SelectReason::Unclaimed,
        detail: String::new(),
    };
    let Some(t) = cert_type else {
        selection.detail = "the certificate type is not detected".into();
        return selection;
    };
    let by_type = for_type(registry, t);
    if by_type.is_empty() {
        selection.detail = format!("no profile accepts type {t}");
        return selection;
    }

    let matched = for_cert(registry, cert, cert_type);
    if let Some(first) = matched.first()
        && first.specificity() > 0
    {
        let top: Vec<_> = matched
            .iter()
            .copied()
            .take_while(|p| p.specificity() == first.specificity())
            .collect();
        if let [only] = top.as_slice() {
            selection.profile = Some(only);
            selection.reason = SelectReason::ByCert;
            selection.detail = format!("asserts role {}", oid::format(&only.required_role_oids[0]));
        } else {
            selection.reason = SelectReason::Ambiguous;
            selection.candidates = top;
            selection.detail = "several profiles match the certificate's roles".into();
        }
        return selection;
    }
    if let Some(profile) = default_for(registry, t) {
        selection.profile = Some(profile);
        selection.reason = SelectReason::ByDefault;
        selection.detail = format!("default for type {t}");
        return selection;
    }
    match matched.as_slice() {
        [only] => {
            selection.profile = Some(only);
            selection.reason = SelectReason::ByCert;
            selection.detail = format!("the only profile that accepts type {t}");
        }
        [] => {
            // Every profile for the type requires a role the certificate lacks: a
            // definite "not one of these", not a question for the user.
            selection.detail = format!(
                "type {t} is accepted by {}, but the certificate asserts none of their roles",
                names(&by_type)
            );
            selection.candidates = by_type;
        }
        _ => {
            selection.reason = SelectReason::Ambiguous;
            selection.detail = format!("type {t} matches several profiles and none owns it");
            selection.candidates = matched;
        }
    }
    selection
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::testing::{TestPki, typed};

    #[test]
    fn registry_invariants() {
        let names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "PROFILES is sorted by name");
        for profile in PROFILES {
            assert!(
                profile
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{profile} is kebab-case"
            );
            assert!(!profile.description.ends_with('.'), "{profile}");
            for t in profile.default_for {
                assert!(
                    profile.accepts(*t),
                    "{profile} defaults to a type it accepts"
                );
                let owners = PROFILES
                    .iter()
                    .filter(|p| p.default_for.contains(t))
                    .count();
                assert_eq!(owners, 1, "{t} has one default profile");
            }
        }
        assert_eq!(
            selector_values(),
            [
                "auto",
                "none",
                "epa-vau-aut",
                "idp-sig",
                "smb-aut",
                "zeta-guard-aut"
            ]
        );
        assert_eq!(lookup("SMB-Aut").map(|p| p.name), Some("smb-aut"));
        assert!(lookup(AUTO).is_none());
        assert!(lookup("idp").is_none());
    }

    fn select(
        name: &str,
    ) -> (
        Option<&'static str>,
        SelectReason,
        Vec<&'static str>,
        String,
    ) {
        let selection = select_for_cert(&typed(name));
        (
            selection.profile.map(|p| p.name),
            selection.reason,
            selection.candidates.iter().map(|p| p.name).collect(),
            selection.detail,
        )
    }

    #[test]
    fn every_oid_a_profile_or_baseline_uses_is_labelled() {
        for t in CertificateType::ALL {
            let info = oid::lookup(&t.oid()).unwrap_or_else(|| panic!("{t} has no label"));
            assert!(!info.reference.is_empty(), "{t}");
            for policy in t.spec().policies {
                assert!(oid::lookup(policy).is_some(), "{t}: policy {policy}");
            }
            for role in t.spec().role_oids {
                assert!(oid::lookup(role).is_some(), "{t}: role {role}");
            }
        }
    }

    #[test]
    fn profile_roles_are_allowed_on_their_types() {
        for profile in PROFILES {
            for role in profile.required_role_oids {
                let allowed = oid::lookup(role).unwrap().certificate_types;
                for t in profile.accepts_types {
                    assert!(
                        allowed.contains(&t.as_str()),
                        "{profile}: {} is not allowed on {t}",
                        oid::format(role)
                    );
                }
            }
        }
    }

    #[test]
    fn automatic_selection() {
        assert_eq!(
            select("type-hci-aut"),
            (
                Some("smb-aut"),
                SelectReason::ByDefault,
                vec![],
                "default for type C.HCI.AUT".into()
            )
        );
        assert_eq!(
            select("role-fd-aut-zeta-guard"),
            (
                Some("zeta-guard-aut"),
                SelectReason::ByCert,
                vec![],
                "asserts role 1.2.276.0.76.4.328 (ZETA Guard)".into()
            )
        );
        assert_eq!(select("role-fd-aut-epa-vau").0, Some("epa-vau-aut"));
        assert_eq!(select("role-fd-sig-idpd").0, Some("idp-sig"));
        assert_eq!(
            select("type-fd-aut"),
            (
                None,
                SelectReason::Unclaimed,
                vec!["epa-vau-aut", "zeta-guard-aut"],
                "type C.FD.AUT is accepted by epa-vau-aut, zeta-guard-aut, but the certificate \
                 asserts none of their roles"
                    .into()
            )
        );
        assert_eq!(
            select("type-fd-tls-s"),
            (
                None,
                SelectReason::Unclaimed,
                vec![],
                "no profile accepts type C.FD.TLS-S".into()
            )
        );
        let undetected = select_for_cert(&typed("none-umbrella-only"));
        assert_eq!(undetected.cert_type, None);
        assert_eq!(undetected.reason, SelectReason::Unclaimed);
    }

    static PLAIN_A: Profile = Profile {
        name: "plain-a",
        required_role_oids: &[],
        ..ZETA_GUARD_AUT
    };
    static PLAIN_B: Profile = Profile {
        name: "plain-b",
        ..PLAIN_A
    };
    static ZETA_TWIN: Profile = Profile {
        name: "zeta-twin",
        ..ZETA_GUARD_AUT
    };

    #[test]
    fn ambiguity_is_reported() {
        let plain = select_from(&[&PLAIN_A, &PLAIN_B], &typed("type-fd-aut"));
        assert_eq!(plain.reason, SelectReason::Ambiguous);
        assert_eq!(
            plain.detail,
            "type C.FD.AUT matches several profiles and none owns it"
        );
        let roles = select_from(
            &[&ZETA_GUARD_AUT, &ZETA_TWIN],
            &typed("role-fd-aut-zeta-guard"),
        );
        assert_eq!(roles.reason, SelectReason::Ambiguous);
        assert_eq!(roles.candidates.len(), 2);
        // A role match outranks a profile that matches anything.
        let ranked = select_from(
            &[&PLAIN_A, &ZETA_GUARD_AUT],
            &typed("role-fd-aut-zeta-guard"),
        );
        assert_eq!(ranked.profile.map(|p| p.name), Some("zeta-guard-aut"));
        let only = select_from(&[&PLAIN_A], &typed("type-fd-aut"));
        assert_eq!(
            (only.reason, only.detail.as_str()),
            (
                SelectReason::ByCert,
                "the only profile that accepts type C.FD.AUT"
            )
        );
    }

    #[test]
    fn a_profile_tightens_but_never_loosens_revocation() {
        use RevocationMode::{Disabled, HardFail, SoftFail};

        let pki = TestPki::new();
        let store = Arc::new(TrustStore::new([pki.rca7.clone()]));
        let mode = |config: RevocationMode, profile: &Profile, t| {
            let config = TrustConfig {
                revocation: config,
                ..TrustConfig::for_anchor(pki.rca7.der().to_vec())
            };
            profile.validator(&config, store.clone(), t).revocation
        };
        let hci = CertificateType::HciAut;
        let fd = CertificateType::FdAut;
        assert_eq!(mode(HardFail, &SMB_AUT, hci), HardFail);
        assert_eq!(mode(SoftFail, &SMB_AUT, hci), SoftFail);
        assert_eq!(mode(SoftFail, &ZETA_GUARD_AUT, fd), HardFail);
        assert_eq!(mode(Disabled, &ZETA_GUARD_AUT, fd), Disabled);
    }

    #[test]
    fn profile_validators_enforce_their_roles() {
        let pki = TestPki::new();
        let config = TrustConfig {
            revocation: RevocationMode::Disabled,
            ..TrustConfig::for_anchor(pki.rca7.der().to_vec())
        };
        let store = Arc::new(TrustStore::new([pki.rca7.clone()]));
        let v = ZETA_GUARD_AUT.validator(&config, store, CertificateType::FdAut);
        assert_eq!(v.required_role_oids, [oid::TECH_ROLE_ZETA_GUARD]);
        let run = |name: &str| {
            let certs = [typed(name), pki.sub_ca_komp.clone()];
            futures_lite::future::block_on(v.validate(
                &certs,
                TestPki::NOW,
                &crate::revocation::Unchecked,
            ))
            .unwrap()
        };
        let zeta = run("role-fd-aut-zeta-guard");
        assert!(zeta.valid, "{:?}", zeta.errors);
        let plain = run("type-fd-aut");
        assert!(plain.has_error(crate::ErrorCode::RoleOidMissing));
        assert_eq!(
            SMB_AUT.effective_role_oids(CertificateType::HciAut),
            CertificateType::HciAut.spec().role_oids
        );
    }
}
