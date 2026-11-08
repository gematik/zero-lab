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

//! A certificate checked against an environment's verified TSL and roots, offline: what
//! `ti pki verify --profile auto --offline` decides, as one document for a web view.
//! `ti-wasm/schemas/check.json` describes it. Revocation is never checked: OCSP needs a
//! network, and the document says so.

#[cfg(feature = "load")]
use std::borrow::Cow;

use super::{Certificate, Finding};
#[cfg(feature = "load")]
use super::{SCHEMA, fingerprint, roots_source};
#[cfg(feature = "load")]
use crate::offline::{self, Material, Outcome, ProfileChoice};
#[cfg(feature = "load")]
use crate::{ChainPosition, Timestamp, ValidationResult};

/// The state of the trust material a check ran against.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TslState {
    /// `valid` or `invalid`; nothing is trusted from an invalid list.
    pub result: &'static str,
    /// Why the list or the roots were rejected.
    pub error: Option<Finding>,
    /// `TSLSequenceNumber`.
    pub sequence_number: Option<u64>,
    /// `NextUpdate`, RFC 3339.
    pub next_update: Option<String>,
    /// `supplied` if the caller's roots.json walked from the anchor, `embedded` otherwise.
    pub roots_source: &'static str,
    /// Why the supplied roots.json was not used.
    pub roots_warning: Option<String>,
}

/// An offline check of a certificate, as one document.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Check {
    /// [`SCHEMA`](super::SCHEMA).
    pub schema: u32,
    /// The environment checked against, e.g. `prod`.
    pub environment: &'static str,
    /// `valid` or `invalid`.
    pub result: &'static str,
    /// The trust material.
    pub tsl: TslState,
    /// The profile the certificate was checked under; `None` when none was detected and
    /// only the chain was checked.
    pub profile: Option<ProfileUsed>,
    /// The gemSpec_PKI type, e.g. `C.HCI.AUT`.
    pub certificate_type: Option<String>,
    /// What made the certificate invalid.
    pub errors: Vec<Issue>,
    /// What did not affect the verdict.
    pub warnings: Vec<Issue>,
    /// Always `not_checked`: revocation needs a network.
    pub revocation: &'static str,
    /// The end entity first, each issuer below it, the root last.
    pub tree: Vec<TrustNode>,
    /// Every certificate of the input, the end entity first, as `ti pki inspect` shows them.
    pub certificates: Vec<Certificate>,
}

/// The profile a certificate was checked under.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ProfileUsed {
    /// The profile, e.g. `smcb`.
    pub name: &'static str,
    /// How it was chosen, e.g. `by_cert`.
    pub reason: &'static str,
    /// Why, for humans.
    pub detail: String,
}

/// An error or warning of the validation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Issue {
    /// The stable code, e.g. `expired`.
    pub code: &'static str,
    /// The certificate concerned; empty when it concerns the chain.
    pub subject: String,
    /// What happened, for humans.
    pub message: String,
}

/// A node of the trust tree.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrustNode {
    /// The certificate's SHA-256 as lower-case hex, as the TSL view files it, when the
    /// TSL lists it as a service.
    pub id: Option<String>,
    /// The common name.
    pub name: String,
    /// What the node is: the end entity's type, `CA`, `root`, `issuer`.
    pub role: String,
    /// Validity, or why the node is not trusted.
    pub note: String,
    /// `ok`, `warn` (trusted but not valid now) or `bad` (not trusted).
    pub state: &'static str,
}

#[cfg(feature = "load")]
impl TslState {
    /// The state of `material`.
    pub fn new(material: &Material) -> Self {
        let roots_source = roots_source(material.roots_source);
        let roots_warning = material.roots_warning.clone();
        match &material.tsl {
            Ok(verified) => TslState {
                result: "valid",
                error: None,
                sequence_number: Some(verified.tsl.sequence_number),
                next_update: verified.tsl.next_update.map(|t| t.to_string()),
                roots_source,
                roots_warning,
            },
            Err(e) => TslState {
                result: "invalid",
                error: Some(e.tsl.as_ref().map_or_else(
                    || Finding {
                        code: "roots_error",
                        code_number: None,
                        rule: "A_28419",
                        detail: e.reason.clone(),
                    },
                    Finding::from,
                )),
                sequence_number: None,
                next_update: None,
                roots_source,
                roots_warning,
            },
        }
    }
}

#[cfg(feature = "load")]
impl Check {
    /// The document of `outcome`, what `check` found for `certs` (the end entity first)
    /// at `now`.
    ///
    /// # Panics
    ///
    /// If `certs` is empty.
    pub fn new(
        check: &offline::Check,
        certs: &[crate::Certificate],
        outcome: &Outcome,
        now: Timestamp,
    ) -> Self {
        let ee = &certs[0];
        let tree = Tree { check, now };
        let mut report = Check {
            schema: SCHEMA,
            environment: check.env().as_str(),
            result: "invalid",
            tsl: TslState::new(check.material()),
            profile: None,
            certificate_type: None,
            errors: Vec::new(),
            warnings: Vec::new(),
            revocation: "not_checked",
            tree: Vec::new(),
            certificates: certs.iter().map(|c| Certificate::new(c, now)).collect(),
        };
        let (profile, result) = match outcome {
            Outcome::Untrusted => {
                report.errors.push(Issue {
                    code: "tsl_invalid",
                    subject: String::new(),
                    message: "the TSL of this environment is not valid; nothing can be trusted"
                        .to_owned(),
                });
                report.tree = vec![tree.node(ee, &ee_role(ee, None), false)];
                return report;
            }
            Outcome::Validated { profile, result } => (profile, result),
        };
        match profile {
            ProfileChoice::Detected {
                profile,
                cert_type,
                reason,
                detail,
            } => {
                report.profile = Some(ProfileUsed {
                    name: profile.name,
                    reason: reason.as_str(),
                    detail: detail.clone(),
                });
                report.certificate_type = Some(cert_type.to_string());
            }
            ProfileChoice::ChainOnly { detail } => report.warnings.push(Issue {
                code: "profile_not_detected",
                subject: ee.subject_cn().to_owned(),
                message: format!("{detail}; checked the chain only"),
            }),
        }
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                report.errors.push(Issue {
                    code: "malformed",
                    subject: ee.subject_cn().to_owned(),
                    message: e.to_string(),
                });
                report.tree = vec![tree.node(ee, &ee_role(ee, None), false)];
                return report;
            }
        };
        report.result = if result.valid { "valid" } else { "invalid" };
        report.errors = result
            .errors
            .iter()
            .map(|e| Issue {
                code: e.code.as_str(),
                subject: e.subject.clone(),
                message: e.message.clone(),
            })
            .collect();
        report
            .warnings
            .extend(result.warnings.iter().map(|w| Issue {
                code: w.code.as_str(),
                subject: w.subject.clone(),
                message: w.message.clone(),
            }));
        report.tree = tree.chain(ee, result, report.certificate_type.as_deref());
        report
    }
}

#[cfg(feature = "load")]
struct Tree<'a> {
    check: &'a offline::Check,
    now: Timestamp,
}

#[cfg(feature = "load")]
impl Tree<'_> {
    /// The chain as built, end entity first; a chain that reaches no trusted root ends in
    /// its missing issuer.
    fn chain(
        &self,
        ee: &crate::Certificate,
        result: &ValidationResult,
        cert_type: Option<&str>,
    ) -> Vec<TrustNode> {
        let reaches_root = result.positions.last() == Some(&ChainPosition::Root);
        let chain: Cow<'_, [crate::Certificate]> = if result.chain.is_empty() {
            Cow::Owned(vec![ee.clone()])
        } else {
            Cow::Borrowed(&result.chain)
        };
        let failed = |cert: &crate::Certificate| {
            result
                .errors
                .iter()
                .any(|e| !e.subject.is_empty() && e.subject == cert.subject_cn())
        };
        let mut nodes: Vec<TrustNode> = chain
            .iter()
            .enumerate()
            .map(|(i, cert)| {
                let role = match result.positions.get(i) {
                    Some(ChainPosition::Root) => "root".to_owned(),
                    Some(ChainPosition::SubCa) => "CA".to_owned(),
                    _ if i == 0 => ee_role(cert, cert_type),
                    _ => "CA".to_owned(),
                };
                self.node(cert, &role, reaches_root && !failed(cert))
            })
            .collect();
        if !reaches_root {
            let top = chain.last().unwrap_or(ee);
            nodes.push(TrustNode {
                id: None,
                name: name_of(top.issuer_cn(), &top.issuer().to_string()),
                role: "issuer".to_owned(),
                note: "not among the trusted CAs of this TSL".to_owned(),
                state: "bad",
            });
        }
        nodes
    }

    fn node(&self, cert: &crate::Certificate, role: &str, trusted: bool) -> TrustNode {
        let now = self.now;
        let note = if now > cert.not_after() {
            format!("expired {}", day(cert.not_after()))
        } else if now < cert.not_before() {
            format!("valid from {}", day(cert.not_before()))
        } else {
            format!("until {}", day(cert.not_after()))
        };
        let state = if !trusted {
            "bad"
        } else if cert.is_valid_at(now) {
            "ok"
        } else {
            "warn"
        };
        TrustNode {
            id: self.listed(cert).then(|| fingerprint(cert)),
            name: name_of(cert.subject_cn(), &cert.subject().to_string()),
            role: role.to_owned(),
            note,
            state,
        }
    }

    /// Whether the TSL lists `cert` as a service's certificate.
    fn listed(&self, cert: &crate::Certificate) -> bool {
        self.check.material().tsl.as_ref().is_ok_and(|verified| {
            verified
                .tsl
                .services
                .iter()
                .any(|s| s.certificate.as_ref() == Some(cert))
        })
    }
}

#[cfg(feature = "load")]
fn ee_role(cert: &crate::Certificate, cert_type: Option<&str>) -> String {
    cert_type.map_or_else(
        || {
            if cert.is_ca() {
                "CA".to_owned()
            } else {
                "end entity".to_owned()
            }
        },
        str::to_owned,
    )
}

#[cfg(feature = "load")]
fn name_of(cn: &str, dn: &str) -> String {
    if cn.is_empty() {
        dn.to_owned()
    } else {
        cn.to_owned()
    }
}

#[cfg(feature = "load")]
fn day(t: Timestamp) -> String {
    t.to_string()
        .split('T')
        .next()
        .unwrap_or_default()
        .to_owned()
}
