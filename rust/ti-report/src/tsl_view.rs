//! The verified TSL of one environment as a single document for a web view: the
//! signature verdict, the list's metadata, the verified roots, every service grouped by
//! provider with the chain of its certificate, and the details of every certificate
//! named, keyed by [`fingerprint`]. `ti-wasm/schemas/tsl-view.json` describes it.
//!
//! An invalid list yields the verdict only: nothing from it may be used, so nothing from
//! it is shown as content.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::Serialize;
use ti_pki::tsl::{self, Intermediate, Rejection, Service, Tsl};
use ti_pki::tsl_signature::{TslCode, VerifiedTsl};
use ti_pki::{Certificate, Env, Tier, Timestamp, TrustConfig, TrustStore, roots};

use crate::oid::TypeOid;
use crate::tsl::{Finding, rejection_code};
use crate::{CertificateInfo, SCHEMA, describe, fingerprint, validity};

/// The document.
#[derive(Clone, Debug, Serialize)]
pub struct TslView {
    /// [`SCHEMA`].
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
    pub signature: Option<SignatureView>,
    /// The list's metadata, for a valid list.
    pub list: Option<ListView>,
    /// The roots the CAs were matched against, for a valid list.
    pub roots: Option<RootsView>,
    /// Totals over the whole list.
    pub counts: Option<Counts>,
    /// The providers in list order, each with its services.
    pub providers: Vec<ProviderView>,
    /// Services the parser left out, with the reason.
    pub skipped: Vec<SkippedView>,
    /// Every certificate the document refers to, by [`fingerprint`].
    pub certificates: BTreeMap<String, CertificateInfo>,
}

/// The signature over the list (`spec/tsl-xmldsig` parts A and B).
#[derive(Clone, Debug, Serialize)]
pub struct SignatureView {
    /// The C.TSL.SIG certificate, by fingerprint.
    pub signer: String,
    /// The TSL signer CA that issued it, by fingerprint.
    pub tsl_signer_ca: String,
    /// The XAdES `SigningTime`, as signed.
    pub signing_time: String,
    /// Findings that leave the list usable, e.g. `no_ocsp_check`.
    pub warnings: Vec<Finding>,
}

/// The list's metadata.
#[derive(Clone, Debug, Serialize)]
pub struct ListView {
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
    pub scheme: SchemeView,
}

/// `SchemeInformation`.
#[derive(Clone, Debug, Serialize)]
pub struct SchemeView {
    /// `TSLVersionIdentifier`.
    pub version_identifier: Option<u32>,
    /// `TSLType`.
    pub tsl_type: String,
    /// `SchemeName`.
    pub scheme_name: String,
    /// `SchemeOperatorName`.
    pub operator_name: String,
    /// The operator's postal addresses.
    pub postal_addresses: Vec<PostalAddressView>,
    /// The operator's electronic addresses (mail, web).
    pub electronic_addresses: Vec<String>,
    /// Where the list is published: `TSLLocation` of the primary pointer.
    pub primary_location: Option<String>,
    /// `TSLLocation` of the backup pointer.
    pub backup_location: Option<String>,
    /// Every pointer to other lists.
    pub pointers: Vec<PointerView>,
}

/// A postal address of the scheme operator.
#[derive(Clone, Debug, Serialize)]
pub struct PostalAddressView {
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
#[derive(Clone, Debug, Serialize)]
pub struct PointerView {
    /// `TSLLocation`.
    pub location: String,
    /// The `AdditionalInformation` OIDs and texts.
    pub additional_information: Vec<String>,
}

/// The roots the list's CAs were matched against.
#[derive(Clone, Debug, Serialize)]
pub struct RootsView {
    /// `supplied` if the caller's roots.json walked from the anchor, `embedded`
    /// otherwise.
    pub source: &'static str,
    /// Why the supplied roots.json was not used.
    pub warning: Option<String>,
    /// The roots, anchor first, then in walk order.
    pub trusted: Vec<RootView>,
}

/// A verified root with the CAs of the list it signed.
#[derive(Clone, Debug, Serialize)]
pub struct RootView {
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
#[derive(Clone, Debug, Serialize)]
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
#[derive(Clone, Debug, Serialize)]
pub struct ProviderView {
    /// `TSPName`.
    pub name: String,
    /// Its services in list order.
    pub services: Vec<ServiceView>,
}

/// A trust service.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceView {
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
    pub chain: Option<ChainView>,
}

/// The chain of a service certificate.
#[derive(Clone, Debug, Serialize)]
pub struct ChainView {
    /// Whether the chain ends in a verified root.
    pub trusted: bool,
    /// The certificates by fingerprint, the service's first, as far as it was built.
    pub path: Vec<String>,
    /// Why it does not: `not_ca`, `self_signed`, `unknown_issuer`, `bad_signature`.
    pub rejection: Option<&'static str>,
}

/// A service the parser left out.
#[derive(Clone, Debug, Serialize)]
pub struct SkippedView {
    /// `TSPName`.
    pub provider: String,
    /// `ServiceName`.
    pub name: String,
    /// Why.
    pub reason: String,
}

/// Verifies `xml` as the TSL of `env` under `config` at `now` and builds the view.
///
/// The roots come from `supplied_roots` if that roots.json walks from the anchor of
/// `config` at `now`, from `config.roots` otherwise; the anchored walk cannot add a root
/// the anchor does not reach, so supplied roots never widen trust. `config` should have
/// passed [`TrustConfig::validate`] for the tier of `env`.
pub fn tsl_view(
    xml: &[u8],
    env: Env,
    config: &TrustConfig,
    supplied_roots: Option<&[u8]>,
    now: Timestamp,
) -> TslView {
    let tier = env.tier();
    let mut view = TslView {
        schema: SCHEMA,
        environment: env.as_str(),
        tier: tier_name(tier),
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
    let verified = match Tsl::parse_verified(xml, config, now) {
        Ok(verified) => verified,
        Err(e) => {
            view.error = Some(Finding::from(&e));
            return view;
        }
    };
    // The presets keep the tiers apart already; this holds even for a hand-built config.
    if verified.tier != tier {
        view.error = Some(Finding {
            code: TslCode::CertificateNotValidMath.as_str(),
            code_number: TslCode::CertificateNotValidMath.number(),
            rule: "TSLSIG-031",
            detail: format!(
                "the list is signed for {}, not for {}",
                tier_name(verified.tier),
                env.as_str()
            ),
        });
        return view;
    }
    view.result = "valid";
    let roots = match load_roots(config, supplied_roots, now) {
        Ok(roots) => roots,
        Err(e) => {
            view.result = "invalid";
            view.error = Some(Finding {
                code: "roots_error",
                code_number: None,
                rule: "A_28419",
                detail: e,
            });
            return view;
        }
    };
    Builder {
        view: &mut view,
        config,
        now,
    }
    .build(&verified, roots);
    view
}

struct Roots {
    trusted: Vec<Certificate>,
    source: &'static str,
    warning: Option<String>,
}

fn load_roots(
    config: &TrustConfig,
    supplied: Option<&[u8]>,
    now: Timestamp,
) -> Result<Roots, String> {
    let mut warning = None;
    if let Some(json) = supplied {
        let with_supplied = TrustConfig {
            roots: Cow::Owned(json.to_vec()),
            ..config.clone()
        };
        match roots::load(&with_supplied, now) {
            Ok(walk) => {
                return Ok(Roots {
                    trusted: walk.trusted,
                    source: "supplied",
                    warning: None,
                });
            }
            Err(e) => warning = Some(format!("supplied roots.json: {e}")),
        }
    }
    let walk = roots::load(config, now).map_err(|e| format!("embedded roots.json: {e}"))?;
    Ok(Roots {
        trusted: walk.trusted,
        source: "embedded",
        warning,
    })
}

const fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Prod => "prod",
        Tier::NonProd => "nonprod",
    }
}

/// A CA of the list a verified root signed, with that root.
struct Kept<'a> {
    ca: &'a Certificate,
    root: &'a Certificate,
}

struct Builder<'a> {
    view: &'a mut TslView,
    config: &'a TrustConfig,
    now: Timestamp,
}

impl Builder<'_> {
    fn build(mut self, verified: &VerifiedTsl, roots: Roots) {
        let list = &verified.tsl;
        self.view.signature = Some(SignatureView {
            signer: self.file(&verified.signer),
            tsl_signer_ca: self.file(&verified.anchor),
            signing_time: verified.signing_time.clone(),
            warnings: verified.warnings.iter().map(Finding::from).collect(),
        });
        self.view.list = Some(ListView {
            id: list.id.clone(),
            sequence_number: list.sequence_number,
            issued_at: list.issued_at.to_string(),
            next_update: list.next_update.map(|t| t.to_string()),
            overdue: list.next_update.is_some_and(|t| self.now >= t),
            scheme: scheme_view(&list.scheme),
        });

        let store = TrustStore::new(roots.trusted.iter().cloned());
        let matched = tsl::match_to_roots(list.intermediate_cas(), &store, &self.config.algorithms);
        // Each kept CA with its root, found once: signature checks dominate the time.
        let kept: Vec<Kept> = matched
            .intermediates
            .iter()
            .filter_map(|i| {
                let root = self.issuing_root(&i.certificate, &store)?;
                Some(Kept {
                    ca: &i.certificate,
                    root,
                })
            })
            .collect();

        let trusted = roots
            .trusted
            .iter()
            .map(|root| RootView {
                fingerprint: self.file(root),
                common_name: root.subject_cn().to_owned(),
                not_after: root.not_after().to_string(),
                validity: validity(root, self.now),
                cas: kept
                    .iter()
                    .filter(|k| k.root == root)
                    .map(|k| fingerprint(k.ca.der()))
                    .collect(),
            })
            .collect();
        self.view.roots = Some(RootsView {
            source: roots.source,
            warning: roots.warning,
            trusted,
        });

        let mut providers: Vec<ProviderView> = Vec::new();
        for service in &list.services {
            let entry = self.service(service, &store, &kept, &matched.rejected);
            match providers.last_mut() {
                Some(current) if current.name == service.provider => current.services.push(entry),
                _ => providers.push(ProviderView {
                    name: service.provider.clone(),
                    services: vec![entry],
                }),
            }
        }
        self.view.counts = Some(Counts {
            providers: providers.len(),
            services: list.services.len(),
            cas_listed: matched.intermediates.len() + matched.rejected.len(),
            cas_kept: matched.intermediates.len(),
            cas_rejected: matched.rejected.len(),
            ocsp: list
                .services
                .iter()
                .filter(|s| s.service_type == tsl::SERVICE_TYPE_OCSP)
                .count(),
            skipped: list.skipped.len(),
        });
        self.view.providers = providers;
        self.view.skipped = list
            .skipped
            .iter()
            .map(|s| SkippedView {
                provider: s.provider.clone(),
                name: s.name.clone(),
                reason: s.reason.clone(),
            })
            .collect();
    }

    fn service(
        &mut self,
        service: &Service,
        store: &TrustStore,
        kept: &[Kept],
        rejected: &[(Intermediate, Rejection)],
    ) -> ServiceView {
        let kind = match service.service_type.as_str() {
            tsl::SERVICE_TYPE_CA_PKC => "ca",
            tsl::SERVICE_TYPE_OCSP => "ocsp",
            tsl::SERVICE_TYPE_TSL_CERT_CHANGE => "tsl_cert_change",
            _ => "other",
        };
        let certificate = service.certificate.as_ref().map(|c| self.file(c));
        let chain = match &service.certificate {
            Some(cert) if service.is_in_accord() => Some(self.chain(cert, store, kept, rejected)),
            _ => None,
        };
        ServiceView {
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

    /// The path from `cert` up to a verified root: a CA the roots kept goes straight to
    /// its root, any other certificate through the kept CA that signed it, or a root.
    fn chain(
        &mut self,
        cert: &Certificate,
        store: &TrustStore,
        kept: &[Kept],
        rejected: &[(Intermediate, Rejection)],
    ) -> ChainView {
        let mut path = vec![self.file(cert)];
        if store.contains(cert) {
            return trusted(path);
        }
        if let Some((_, reason)) = rejected.iter().find(|(i, _)| &i.certificate == cert) {
            return untrusted(path, *reason);
        }
        if let Some(k) = kept.iter().find(|k| k.ca == cert) {
            path.push(self.file(k.root));
            return trusted(path);
        }
        if let Some(k) = kept.iter().find(|k| self.signed_by(cert, k.ca)) {
            path.push(self.file(k.ca));
            path.push(self.file(k.root));
            return trusted(path);
        }
        if let Some(root) = self.issuing_root(cert, store) {
            path.push(self.file(root));
            return trusted(path);
        }
        let named = kept.iter().any(|k| k.ca.subject_der() == cert.issuer_der());
        untrusted(
            path,
            if named {
                Rejection::BadSignature
            } else {
                Rejection::UnknownIssuer
            },
        )
    }

    fn issuing_root<'s>(
        &self,
        cert: &Certificate,
        store: &'s TrustStore,
    ) -> Option<&'s Certificate> {
        store.roots().iter().find(|root| self.signed_by(cert, root))
    }

    fn signed_by(&self, cert: &Certificate, issuer: &Certificate) -> bool {
        cert.issuer_der() == issuer.subject_der()
            && cert
                .verify_signed_by(issuer, &self.config.algorithms)
                .is_ok()
    }

    /// Files `cert` under its fingerprint and returns that.
    fn file(&mut self, cert: &Certificate) -> String {
        let key = fingerprint(cert.der());
        if !self.view.certificates.contains_key(&key) {
            self.view
                .certificates
                .insert(key.clone(), describe(cert, self.now));
        }
        key
    }
}

fn trusted(path: Vec<String>) -> ChainView {
    ChainView {
        trusted: true,
        path,
        rejection: None,
    }
}

fn untrusted(path: Vec<String>, reason: Rejection) -> ChainView {
    ChainView {
        trusted: false,
        path,
        rejection: Some(rejection_code(reason)),
    }
}

fn scheme_view(scheme: &tsl::SchemeInfo) -> SchemeView {
    SchemeView {
        version_identifier: scheme.version_identifier,
        tsl_type: scheme.tsl_type.clone(),
        scheme_name: scheme.scheme_name.clone(),
        operator_name: scheme.operator_name.clone(),
        postal_addresses: scheme
            .postal_addresses
            .iter()
            .map(|a| PostalAddressView {
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
            .map(|p| PointerView {
                location: p.location.clone(),
                additional_information: p.additional_information.clone(),
            })
            .collect(),
    }
}
