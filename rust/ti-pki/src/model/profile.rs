/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The validation profiles as `ti pki profiles` shows them: what each accepts and
//! requires, and which CAs of a verified TSL may issue its types.

use crate::profile::Profile;
use crate::revocation::RevocationMode;
use crate::{CertificateType, Env, TrustStore, checks};

use super::Oid;

/// A validation profile.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ValidationProfile {
    /// Its name, e.g. `hci-aut`.
    pub name: &'static str,
    /// One line.
    pub description: &'static str,
    /// `hard-fail`, `soft-fail` or `disabled`.
    pub revocation: &'static str,
    /// The certificate types it is meant for.
    pub accepts_types: Vec<&'static str>,
    /// The types it is the automatic default for.
    pub default_for: Vec<&'static str>,
    /// The roles an end entity must assert one of; empty for no requirement.
    pub required_role_oids: Vec<Oid>,
}

impl ValidationProfile {
    /// The projection of `profile`.
    pub fn new(profile: &Profile) -> Self {
        ValidationProfile {
            name: profile.name,
            description: profile.description,
            revocation: revocation(profile.revocation),
            accepts_types: profile.accepts_types.iter().map(|t| t.as_str()).collect(),
            default_for: profile.default_for.iter().map(|t| t.as_str()).collect(),
            required_role_oids: profile.required_role_oids.iter().map(Oid::new).collect(),
        }
    }
}

fn revocation(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}

/// The baseline a certificate type imposes, with a profile's overlay applied.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TypeRequirements {
    /// The type, e.g. `C.HCI.AUT`.
    pub certificate_type: &'static str,
    /// Every one of these key usages.
    pub key_usage: Vec<&'static str>,
    /// One of these extended key usages.
    pub extended_key_usage: Vec<String>,
    /// Every one of these policies.
    pub policies: Vec<Oid>,
    /// One of these must be asserted; empty for no requirement.
    pub role_oids: Vec<Oid>,
}

impl TypeRequirements {
    /// What `profile` requires of a certificate of type `t`.
    pub fn new(profile: &Profile, t: CertificateType) -> Self {
        let spec = t.spec();
        TypeRequirements {
            certificate_type: t.as_str(),
            key_usage: spec
                .key_usage
                .iter()
                .map(|bit| checks::key_usage_name(*bit))
                .collect(),
            extended_key_usage: spec
                .ext_key_usage
                .iter()
                .map(checks::ext_key_usage_name)
                .collect(),
            policies: spec
                .policies
                .iter()
                .chain(profile.extra_policies)
                .map(Oid::new)
                .collect(),
            role_oids: profile
                .effective_role_oids(t)
                .iter()
                .map(Oid::new)
                .collect(),
        }
    }
}

/// The CAs under a store's verified roots whose entry in its verified TSL allows one of
/// a profile's types.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TslCas {
    /// The environment of the TSL.
    pub environment: &'static str,
    /// The CAs, in TSL order.
    pub cas: Vec<TslCa>,
}

/// A CA of [`TslCas`].
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TslCa {
    /// Its subject's common name.
    pub common_name: String,
    /// The TSP the TSL lists the CA under.
    pub provider: String,
    /// Of the profile's types, those the TSL entry names.
    pub types: Vec<&'static str>,
}

impl TslCas {
    /// The CAs of `store`, verified for `env`, that may issue a type `profile` accepts.
    pub fn new(store: &TrustStore, profile: &Profile, env: Env) -> Self {
        let cas = store
            .intermediates()
            .iter()
            .filter_map(|ca| {
                let listed = store.tsl_types_of(ca)?;
                let types: Vec<&'static str> = profile
                    .accepts_types
                    .iter()
                    .filter(|t| listed.contains(&t.oid()))
                    .map(|t| t.as_str())
                    .collect();
                (!types.is_empty()).then(|| TslCa {
                    common_name: ca.subject_cn().to_owned(),
                    provider: store.provider_of(ca).unwrap_or_default().to_owned(),
                    types,
                })
            })
            .collect();
        TslCas {
            environment: env.as_str(),
            cas,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;

    #[test]
    fn a_profile_shows_its_types_roles_and_revocation() {
        let hci = ValidationProfile::new(&profile::HCI_AUT);
        assert_eq!(hci.name, "hci-aut");
        assert_eq!(hci.revocation, "hard-fail");
        assert_eq!(hci.default_for, ["C.HCI.AUT"]);
        let requirements = TypeRequirements::new(&profile::HCI_AUT, CertificateType::HciAut);
        assert_eq!(requirements.key_usage, ["digitalSignature"]);
        assert_eq!(requirements.extended_key_usage, ["id-kp-clientAuth"]);
        assert!(!requirements.role_oids.is_empty());
    }
}
