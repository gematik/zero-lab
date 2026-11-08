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

//! The verified TSL of one environment as a single document for a web view: the
//! signature verdict, the list's metadata, the verified roots, every service grouped by
//! provider with the chain of its certificate, and the details of every certificate
//! named, keyed by their SHA-256 in lower-case hex. `ti-wasm/schemas/tsl-view.json` describes it.
//!
//! An invalid list yields the verdict only: nothing from it may be used, so nothing from
//! it is shown as content.

use std::collections::BTreeMap;

use super::{Certificate, Finding, TypeOid};
#[cfg(feature = "load")]
use super::{SCHEMA, fingerprint, rejection_code, roots_source, validity};
#[cfg(feature = "load")]
use crate::offline::{self, TslFailure};
#[cfg(feature = "load")]
use crate::{Env, Timestamp};

/// A verified TSL as one document.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Tsl {
    /// [`SCHEMA`](super::SCHEMA).
    pub schema: u32,
    /// The environment the list was verified for, e.g. `prod`.
    pub environment: &'static str,
    /// `prod` or `nonprod`: the tier of the environment, which the list's TSL signer CA
    /// had to match.
    pub tier: &'static str,
    /// `valid` or `invalid`.
    pub result: &'static str,
    /// Why the list is invalid.
    pub error: Option<Finding>,
    /// The signature, for a valid list.
    pub signature: Option<Signature>,
    /// The list's metadata, for a valid list.
    pub list: Option<List>,
    /// The roots the CAs were matched against, for a valid list.
    pub roots: Option<Roots>,
    /// Totals over the whole list.
    pub counts: Option<Counts>,
    /// The providers in list order, each with its services.
    pub providers: Vec<Provider>,
    /// Services the parser left out, with the reason.
    pub skipped: Vec<Skipped>,
    /// Every certificate the document refers to, by their SHA-256 in lower-case hex.
    pub certificates: BTreeMap<String, Certificate>,
}

/// The signature over the list (`spec/tsl-detached`, `spec/tsl-xmldsig` part B).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Signature {
    /// The C.TSL.SIG certificate, by fingerprint.
    pub signer: String,
    /// The TSL signer CA that issued it, by fingerprint.
    pub tsl_signer_ca: String,
    /// Findings that leave the list usable, e.g. `no_ocsp_check`.
    pub warnings: Vec<Finding>,
}

/// The list's metadata.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct List {
    /// The `Id` attribute.
    pub id: String,
    /// `TSLSequenceNumber`.
    pub sequence_number: u64,
    /// `ListIssueDateTime`, RFC 3339.
    pub issued_at: String,
    /// `NextUpdate`, RFC 3339.
    pub next_update: Option<String>,
    /// Past `next_update`, within the grace period.
    pub overdue: bool,
    /// `SchemeInformation`.
    pub scheme: Scheme,
}

/// `SchemeInformation`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Scheme {
    /// `TSLVersionIdentifier`.
    pub version_identifier: Option<u32>,
    /// `TSLType`.
    pub tsl_type: String,
    /// `SchemeName`.
    pub scheme_name: String,
    /// `SchemeOperatorName`.
    pub operator_name: String,
    /// The operator's postal addresses.
    pub postal_addresses: Vec<PostalAddress>,
    /// The operator's electronic addresses (mail, web).
    pub electronic_addresses: Vec<String>,
    /// Where the list is published: `TSLLocation` of the primary pointer.
    pub primary_location: Option<String>,
    /// `TSLLocation` of the backup pointer.
    pub backup_location: Option<String>,
    /// Every pointer to other lists.
    pub pointers: Vec<Pointer>,
}

/// A postal address of the scheme operator.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PostalAddress {
    /// `StreetAddress`.
    pub street: String,
    /// `PostalCode`.
    pub postal_code: String,
    /// `Locality`.
    pub locality: String,
    /// `StateOrProvince`.
    pub state: String,
    /// `CountryName`.
    pub country: String,
}

/// A `PointersToOtherTSL` entry.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Pointer {
    /// `TSLLocation`.
    pub location: String,
    /// The `AdditionalInformation` OIDs and texts.
    pub additional_information: Vec<String>,
}

/// The roots the list's CAs were matched against.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Roots {
    /// `supplied` if the caller's roots.json walked from the anchor, `embedded`
    /// otherwise.
    pub source: &'static str,
    /// Why the supplied roots.json was not used.
    pub warning: Option<String>,
    /// The roots, anchor first, then in walk order.
    pub trusted: Vec<Root>,
}

/// A verified root with the CAs of the list it signed.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Root {
    /// By fingerprint.
    pub fingerprint: String,
    /// The subject's common name.
    pub common_name: String,
    /// RFC 3339.
    pub not_after: String,
    /// `valid`, `expired` or `not_yet_valid`.
    pub validity: &'static str,
    /// The CAs it signed, by fingerprint, in list order.
    pub cas: Vec<String>,
}

/// Totals over the whole list.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Counts {
    /// The providers.
    pub providers: usize,
    /// Every service.
    pub services: usize,
    /// CA services in accord with a certificate: the candidates.
    pub cas_listed: usize,
    /// Of those, signed by a verified root.
    pub cas_kept: usize,
    /// Of those, signed by no verified root.
    pub cas_rejected: usize,
    /// OCSP services.
    pub ocsp: usize,
    /// Services the parser left out.
    pub skipped: usize,
}

/// A trust service provider.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Provider {
    /// `TSPName`.
    pub name: String,
    /// Its services in list order.
    pub services: Vec<Service>,
}

/// A trust service.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Service {
    /// `ServiceName`.
    pub name: String,
    /// `ServiceTypeIdentifier`.
    pub service_type: String,
    /// `ca`, `ocsp`, `tsl_cert_change` or `other`.
    pub kind: &'static str,
    /// `ServiceStatus`.
    pub status: String,
    /// Whether the status is in accord (or granted).
    pub in_accord: bool,
    /// `StatusStartingTime`, RFC 3339.
    pub status_starting_time: Option<String>,
    /// `ServiceSupplyPoint`s, e.g. OCSP URLs.
    pub supply_points: Vec<String>,
    /// The certificate types the list states for the service (Tab_PKI_405).
    pub type_oids: Vec<TypeOid>,
    /// The service certificate, by fingerprint.
    pub certificate: Option<String>,
    /// The chain from the certificate to a verified root, for a service in accord.
    pub chain: Option<Chain>,
}

/// The chain of a service certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Chain {
    /// Whether the chain ends in a verified root.
    pub trusted: bool,
    /// The certificates by fingerprint, the service's first, as far as it was built.
    pub path: Vec<String>,
    /// Why it does not: `not_ca`, `self_signed`, `unknown_issuer`, `bad_signature`.
    pub rejection: Option<&'static str>,
}

/// A service the parser left out.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Skipped {
    /// `TSPName`.
    pub provider: String,
    /// `ServiceName`.
    pub name: String,
    /// Why.
    pub reason: String,
}

#[cfg(feature = "load")]
impl Tsl {
    /// The view of `verified`, the outcome of [`offline::Tsl::verify`] for `env`, its
    /// certificates described at `now`. A failed list yields the verdict only: nothing
    /// from it may be used, so nothing from it is shown as content.
    pub fn new(env: Env, verified: &Result<offline::Tsl, TslFailure>, now: Timestamp) -> Self {
        let mut view = Tsl {
            schema: SCHEMA,
            environment: env.as_str(),
            tier: env.tier().as_str(),
            result: "invalid",
            error: None,
            signature: None,
            list: None,
            roots: None,
            counts: None,
            providers: Vec::new(),
            skipped: Vec::new(),
            certificates: BTreeMap::new(),
        };
        match verified {
            Ok(tsl) => {
                view.result = "valid";
                Builder {
                    view: &mut view,
                    now,
                }
                .build(tsl);
            }
            Err(TslFailure::Tsl(e)) => view.error = Some(Finding::from(e)),
            Err(TslFailure::Roots(reason)) => {
                view.error = Some(Finding {
                    code: "roots_error",
                    code_number: None,
                    rule: "A_28419",
                    detail: reason.clone(),
                });
            }
        }
        view
    }
}

#[cfg(feature = "load")]
struct Builder<'a> {
    view: &'a mut Tsl,
    now: Timestamp,
}

#[cfg(feature = "load")]
impl Builder<'_> {
    fn build(mut self, tsl: &offline::Tsl) {
        let verified = &tsl.verified;
        let list = &verified.tsl;
        self.view.signature = Some(Signature {
            signer: self.file(&verified.signer),
            tsl_signer_ca: self.file(&verified.anchor),
            warnings: verified.warnings.iter().map(Finding::from).collect(),
        });
        self.view.list = Some(List {
            id: list.id.clone(),
            sequence_number: list.sequence_number,
            issued_at: list.issued_at.to_string(),
            next_update: list.next_update.map(|t| t.to_string()),
            overdue: list.next_update.is_some_and(|t| self.now >= t),
            scheme: scheme(&list.scheme),
        });

        let trusted = tsl
            .roots
            .iter()
            .map(|root| Root {
                fingerprint: self.file(root),
                common_name: root.subject_cn().to_owned(),
                not_after: root.not_after().to_string(),
                validity: validity(root, self.now),
                cas: tsl
                    .kept
                    .iter()
                    .filter(|k| &k.root == root)
                    .map(|k| fingerprint(&k.ca))
                    .collect(),
            })
            .collect();
        self.view.roots = Some(Roots {
            source: roots_source(tsl.roots_source),
            warning: tsl.roots_warning.clone(),
            trusted,
        });

        let mut providers: Vec<Provider> = Vec::new();
        for (service, chain) in list.services.iter().zip(&tsl.chains) {
            let entry = self.service(service, chain.as_ref());
            match providers.last_mut() {
                Some(current) if current.name == service.provider => current.services.push(entry),
                _ => providers.push(Provider {
                    name: service.provider.clone(),
                    services: vec![entry],
                }),
            }
        }
        let matched = &tsl.matched;
        self.view.counts = Some(Counts {
            providers: providers.len(),
            services: list.services.len(),
            cas_listed: matched.intermediates.len() + matched.rejected.len(),
            cas_kept: matched.intermediates.len(),
            cas_rejected: matched.rejected.len(),
            ocsp: list
                .services
                .iter()
                .filter(|s| s.service_type == crate::tsl::SERVICE_TYPE_OCSP)
                .count(),
            skipped: list.skipped.len(),
        });
        self.view.providers = providers;
        self.view.skipped = list
            .skipped
            .iter()
            .map(|s| Skipped {
                provider: s.provider.clone(),
                name: s.name.clone(),
                reason: s.reason.clone(),
            })
            .collect();
    }

    fn service(
        &mut self,
        service: &crate::tsl::Service,
        chain: Option<&offline::ServiceChain>,
    ) -> Service {
        let kind = match service.service_type.as_str() {
            crate::tsl::SERVICE_TYPE_CA_PKC => "ca",
            crate::tsl::SERVICE_TYPE_OCSP => "ocsp",
            crate::tsl::SERVICE_TYPE_TSL_CERT_CHANGE => "tsl_cert_change",
            _ => "other",
        };
        let certificate = service.certificate.as_ref().map(|c| self.file(c));
        let chain = chain.map(|chain| Chain {
            trusted: chain.rejection.is_none(),
            path: chain.path.iter().map(|c| self.file(c)).collect(),
            rejection: chain.rejection.map(rejection_code),
        });
        Service {
            name: service.name.clone(),
            service_type: service.service_type.clone(),
            kind,
            status: service.status.clone(),
            in_accord: service.is_in_accord(),
            status_starting_time: service.status_starting_time.map(|t| t.to_string()),
            supply_points: service.supply_points.clone(),
            type_oids: service.type_oids.iter().map(TypeOid::new).collect(),
            certificate,
            chain,
        }
    }

    /// Files `cert` under its fingerprint and returns that.
    fn file(&mut self, cert: &crate::Certificate) -> String {
        let key = fingerprint(cert);
        if !self.view.certificates.contains_key(&key) {
            self.view
                .certificates
                .insert(key.clone(), Certificate::new(cert, self.now));
        }
        key
    }
}

#[cfg(feature = "load")]
fn scheme(scheme: &crate::tsl::SchemeInfo) -> Scheme {
    Scheme {
        version_identifier: scheme.version_identifier,
        tsl_type: scheme.tsl_type.clone(),
        scheme_name: scheme.scheme_name.clone(),
        operator_name: scheme.operator_name.clone(),
        postal_addresses: scheme
            .postal_addresses
            .iter()
            .map(|a| PostalAddress {
                street: a.street.clone(),
                postal_code: a.postal_code.clone(),
                locality: a.locality.clone(),
                state: a.state.clone(),
                country: a.country.clone(),
            })
            .collect(),
        electronic_addresses: scheme.electronic_addresses.clone(),
        primary_location: scheme.primary_location().map(str::to_owned),
        backup_location: scheme.backup_location().map(str::to_owned),
        pointers: scheme
            .pointers
            .iter()
            .map(|p| Pointer {
                location: p.location.clone(),
                additional_information: p.additional_information.clone(),
            })
            .collect(),
    }
}
