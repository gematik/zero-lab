//! Per-certificate predicates run by path validation on the end entity: key usage,
//! extended key usage, certificate policies, the name the end entity must carry, and
//! admission roles. Each failure is a
//! [`ValidationError`] whose message names what was required and what was present.

use std::sync::Arc;

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

use crate::Certificate;
use crate::error::{ErrorCode, ValidationError};

/// A check on one certificate. Cheap and side-effect free; network work such as OCSP
/// belongs to revocation, not here.
pub type CertificateCheck = Arc<dyn Fn(&Certificate) -> Result<(), ValidationError> + Send + Sync>;

/// `anyExtendedKeyUsage`, which satisfies any extended key usage requirement.
pub const ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");

/// Requires every bit of `required`; further bits are allowed. A certificate without a
/// key usage extension has no bits.
pub fn key_usage(required: &[KeyUsages]) -> CertificateCheck {
    let required = required.to_vec();
    Arc::new(move |cert| {
        let have = cert.key_usage().map(|ku| ku.0).unwrap_or_default();
        if required.iter().all(|bit| have.contains(*bit)) {
            return Ok(());
        }
        Err(ValidationError::new(
            ErrorCode::KeyUsageMismatch,
            format!(
                "required KeyUsage {} missing (have {})",
                describe_key_usage(required.iter().copied()),
                describe_key_usage(have.into_iter())
            ),
        )
        .with_subject(cert.subject_cn()))
    })
}

/// Requires one of `allowed` among the extended key usages (or `anyExtendedKeyUsage`).
pub fn any_ext_key_usage(allowed: &[ObjectIdentifier]) -> CertificateCheck {
    let allowed = allowed.to_vec();
    Arc::new(move |cert| {
        let have = cert.ext_key_usage();
        if have.contains(&ANY_EXTENDED_KEY_USAGE) || allowed.iter().any(|eku| have.contains(eku)) {
            return Ok(());
        }
        let names: Vec<String> = allowed.iter().map(ext_key_usage_name).collect();
        Err(ValidationError::new(
            ErrorCode::KeyUsageMismatch,
            format!(
                "certificate ExtKeyUsage matches none of: {}",
                names.join(", ")
            ),
        )
        .with_subject(cert.subject_cn()))
    })
}

/// Requires every policy in `required`; empty means no requirement.
pub fn certificate_policies(required: &[ObjectIdentifier]) -> CertificateCheck {
    let required = required.to_vec();
    Arc::new(move |cert| {
        let missing: Vec<ObjectIdentifier> = required
            .iter()
            .filter(|policy| !cert.has_policy(policy))
            .copied()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        Err(ValidationError::new(
            ErrorCode::PolicyMismatch,
            format!(
                "required CertificatePolicy missing: {} (have {})",
                oids(&missing),
                oids(cert.policies())
            ),
        )
        .with_subject(cert.subject_cn()))
    })
}

/// Requires the fully qualified domain name the end entity's commonName leads with to
/// be `expected`, ignoring case and a trailing dot (A_30046 (5) of C_12791). A
/// commonName that does not start with a domain name (`Dr. Arzt`, an address) passes:
/// the requirement covers only certificates that name a host.
pub fn fqdn(expected: &str) -> CertificateCheck {
    let expected = expected.trim_end_matches('.').to_ascii_lowercase();
    Arc::new(move |cert| {
        let Some(named) = leading_fqdn(cert.subject_cn()) else {
            return Ok(());
        };
        if named.trim_end_matches('.').eq_ignore_ascii_case(&expected) {
            return Ok(());
        }
        Err(ValidationError::new(
            ErrorCode::FqdnMismatch,
            format!("commonName names {named}, expected {expected}"),
        )
        .with_subject(cert.subject_cn()))
    })
}

/// The domain name a commonName starts with: the first word, if it has at least two
/// labels of letters, digits and hyphens, and a top-level label that is not all digits
/// (which rules out IPv4 addresses). TI test certificates append ` TEST-ONLY`.
fn leading_fqdn(common_name: &str) -> Option<&str> {
    let name = common_name.split_whitespace().next()?;
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let is_label = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let top = labels.last()?;
    (labels.len() >= 2
        && name.len() <= 254
        && labels.iter().all(is_label)
        && !top.bytes().all(|b| b.is_ascii_digit()))
    .then_some(name)
}

/// Requires one of `allowed` among the admission roles; empty means no requirement. A
/// certificate without an admission extension asserts no roles.
pub fn role_oid(allowed: &[ObjectIdentifier]) -> CertificateCheck {
    let allowed = allowed.to_vec();
    Arc::new(move |cert| {
        if allowed.is_empty() {
            return Ok(());
        }
        let have = match cert.admission() {
            Ok(admission) => admission.map(|a| a.profession_oids).unwrap_or_default(),
            Err(e) => {
                return Err(ValidationError::new(
                    ErrorCode::RoleOidMissing,
                    "role OID extraction failed",
                )
                .with_subject(cert.subject_cn())
                .with_cause(e));
            }
        };
        if have.iter().any(|role| allowed.contains(role)) {
            return Ok(());
        }
        Err(ValidationError::new(
            ErrorCode::RoleOidMissing,
            format!(
                "required role OID missing: have {}, want one of {}",
                oids(&have),
                oids(&allowed)
            ),
        )
        .with_subject(cert.subject_cn()))
    })
}

/// The RFC 5280 name of a key usage bit, e.g. `digitalSignature`; `contentCommitment`
/// for the bit formerly called nonRepudiation.
pub const fn key_usage_name(bit: KeyUsages) -> &'static str {
    match bit {
        KeyUsages::DigitalSignature => "digitalSignature",
        KeyUsages::NonRepudiation => "contentCommitment",
        KeyUsages::KeyEncipherment => "keyEncipherment",
        KeyUsages::DataEncipherment => "dataEncipherment",
        KeyUsages::KeyAgreement => "keyAgreement",
        KeyUsages::KeyCertSign => "keyCertSign",
        KeyUsages::CRLSign => "cRLSign",
        KeyUsages::EncipherOnly => "encipherOnly",
        KeyUsages::DecipherOnly => "decipherOnly",
    }
}

fn describe_key_usage(bits: impl Iterator<Item = KeyUsages>) -> String {
    let names: Vec<&str> = bits.map(key_usage_name).collect();
    if names.is_empty() {
        "(none)".into()
    } else {
        names.join("|")
    }
}

/// The name of an extended key usage, e.g. `id-kp-clientAuth`; the OID for one this
/// crate does not name.
pub fn ext_key_usage_name(eku: &ObjectIdentifier) -> String {
    let name = match eku.to_string().as_str() {
        "2.5.29.37.0" => "any",
        "1.3.6.1.5.5.7.3.1" => "id-kp-serverAuth",
        "1.3.6.1.5.5.7.3.2" => "id-kp-clientAuth",
        "1.3.6.1.5.5.7.3.3" => "id-kp-codeSigning",
        "1.3.6.1.5.5.7.3.4" => "id-kp-emailProtection",
        "1.3.6.1.5.5.7.3.8" => "id-kp-timeStamping",
        "1.3.6.1.5.5.7.3.9" => "id-kp-OCSPSigning",
        // ETSI TS 102 231, the C.TSL.SIG certificate's only extended key usage.
        "0.4.0.2231.3.0" => "id-tsl-kp-tslSigning",
        other => return other.to_owned(),
    };
    name.to_owned()
}

fn oids(list: &[ObjectIdentifier]) -> String {
    if list.is_empty() {
        return "(none)".into();
    }
    let parts: Vec<String> = list.iter().map(ToString::to_string).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::testing::{TestPki, typed};

    #[test]
    fn extended_key_usage_names() {
        assert_eq!(
            ext_key_usage_name(&crate::cert_type::TSL_SIGNING),
            "id-tsl-kp-tslSigning"
        );
        assert_eq!(
            ext_key_usage_name(&ObjectIdentifier::new_unwrap("1.2.3")),
            "1.2.3"
        );
    }

    #[test]
    fn fqdn_in_the_common_name() {
        let pki = TestPki::new();
        // CN "zeta.ti-dienste.de TEST-ONLY"
        fqdn("zeta.ti-dienste.de")(&pki.ee_zeta).unwrap();
        fqdn("ZETA.ti-dienste.de.")(&pki.ee_zeta).unwrap();
        let error = fqdn("popp.ti-dienste.de")(&pki.ee_zeta).unwrap_err();
        assert_eq!(error.code, ErrorCode::FqdnMismatch);
        assert_eq!(
            error.message,
            "commonName names zeta.ti-dienste.de, expected popp.ti-dienste.de"
        );
        // "Dr. Arzt TEST-ONLY" names no host.
        fqdn("zeta.ti-dienste.de")(&pki.ee_arzt).unwrap();

        for (cn, named) in [
            (
                "erp.zentral.erp.splitdns.ti-dienste.de",
                Some("erp.zentral.erp.splitdns.ti-dienste.de"),
            ),
            ("host.example. TEST-ONLY", Some("host.example.")),
            ("Dr. Arzt", None),
            ("10.0.0.1", None),
            ("localhost", None),
            ("-bad.example", None),
            ("*.ti-dienste.de", None),
            ("", None),
        ] {
            assert_eq!(leading_fqdn(cn), named, "{cn:?}");
        }
    }

    #[test]
    fn key_usage_requires_every_bit() {
        let pki = TestPki::new();
        key_usage(&[KeyUsages::DigitalSignature])(&pki.ee_arzt).unwrap();
        let error = key_usage(&[KeyUsages::KeyCertSign])(&pki.ee_arzt).unwrap_err();
        assert_eq!(error.code, ErrorCode::KeyUsageMismatch);
        assert_eq!(
            error.message,
            "required KeyUsage keyCertSign missing (have digitalSignature)"
        );
        let hp_aut = typed("type-hp-aut");
        key_usage(&[KeyUsages::DigitalSignature, KeyUsages::KeyAgreement])(&hp_aut).unwrap();
        assert!(
            key_usage(&[KeyUsages::DigitalSignature, KeyUsages::NonRepudiation])(&hp_aut).is_err()
        );
    }

    #[test]
    fn any_of_the_ext_key_usages() {
        let pki = TestPki::new();
        any_ext_key_usage(&[crate::cert_type::SERVER_AUTH, crate::cert_type::CLIENT_AUTH])(
            &pki.ee_arzt,
        )
        .unwrap();
        let error = any_ext_key_usage(&[crate::cert_type::SERVER_AUTH])(&pki.ee_arzt).unwrap_err();
        assert_eq!(
            error.message,
            "certificate ExtKeyUsage matches none of: id-kp-serverAuth"
        );
    }

    #[test]
    fn policies_all_required() {
        let cert = typed("type-fd-aut");
        certificate_policies(&[crate::oid::POLICY_GEM_OR_CP, crate::oid::CERT_TYPE_FD_AUT])(&cert)
            .unwrap();
        certificate_policies(&[])(&cert).unwrap();
        let error = certificate_policies(&[crate::oid::POLICY_HBA_CP])(&cert).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyMismatch);
        assert!(
            error
                .message
                .starts_with("required CertificatePolicy missing: [1.2.276.0.76.4.145]")
        );
    }

    #[test]
    fn roles_one_of() {
        let pki = TestPki::new();
        role_oid(&[crate::oid::PROF_ARZT, crate::oid::PROF_ZAHNARZT])(&pki.ee_arzt).unwrap();
        role_oid(&[])(&pki.ee_zeta).unwrap();
        let error = role_oid(&[crate::oid::PROF_ZAHNARZT])(&pki.ee_zeta).unwrap_err();
        assert_eq!(error.code, ErrorCode::RoleOidMissing);
        assert_eq!(
            error.message,
            "required role OID missing: have (none), want one of [1.2.276.0.76.4.31]"
        );
    }
}
