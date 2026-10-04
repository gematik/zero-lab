//! A certificate checked against an environment's verified TSL and roots, offline: what
//! `ti pki verify --profile auto --offline` decides, as one document for a web view.
//! `ti-wasm/schemas/check.json` describes it.
//!
//! [`CheckContext`] verifies the trust material once; [`CheckContext::check`] then judges
//! any number of certificates against it. Revocation is never checked: OCSP needs a
//! network, and the report says so.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use core::pin::pin;
use core::task::{Context, Poll, Waker};

use serde::Serialize;
use ti_pki::profile::select_for_cert;
use ti_pki::revocation::{RevocationMode, Unchecked};
use ti_pki::{
    Certificate, ChainPosition, Env, Timestamp, TrustConfig, TrustStore, ValidationResult,
    Validator,
};

use crate::tsl::Finding;
use crate::{CertificateInfo, SCHEMA, describe, fingerprint};

/// The trust material of one environment, verified, ready to check certificates against.
pub struct CheckContext {
    env: Env,
    config: TrustConfig,
    store: Option<Arc<TrustStore>>,
    tsl: TslState,
    /// Fingerprints of the certificates the TSL lists as services.
    listed: HashSet<String>,
}

/// The state of the trust material a check ran against.
#[derive(Clone, Debug, Serialize)]
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

/// The document.
#[derive(Clone, Debug, Serialize)]
pub struct CheckReport {
    /// [`SCHEMA`].
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
    pub certificates: Vec<CertificateInfo>,
}

/// The profile a certificate was checked under.
#[derive(Clone, Debug, Serialize)]
pub struct ProfileUsed {
    /// The profile, e.g. `smcb`.
    pub name: &'static str,
    /// How it was chosen, e.g. `by_cert`.
    pub reason: &'static str,
    /// Why, for humans.
    pub detail: String,
}

/// An error or warning of the validation.
#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    /// The stable code, e.g. `expired`.
    pub code: &'static str,
    /// The certificate concerned; empty when it concerns the chain.
    pub subject: String,
    /// What happened, for humans.
    pub message: String,
}

/// A node of the trust tree.
#[derive(Clone, Debug, Serialize)]
pub struct TrustNode {
    /// The certificate's [`fingerprint`] when the TSL lists it as a service.
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

impl CheckContext {
    /// Verifies the TSL `tsl_xml` for `env` under `config` at `now`, with the roots of
    /// `supplied_roots` if that roots.json walks from the anchor, else `config.roots`.
    /// An invalid list is not an error: every check against it then reports it.
    pub fn new(
        env: Env,
        config: TrustConfig,
        supplied_roots: Option<&[u8]>,
        tsl_xml: &[u8],
        now: Timestamp,
    ) -> Self {
        let mut roots_warning = None;
        let attempt = |roots: &[u8]| TrustStore::from_material(&config, roots, tsl_xml, now);
        let outcome = match supplied_roots {
            Some(json) => match attempt(json) {
                // A TSL that fails fails with any roots; only a roots failure falls back.
                Err(e) if e.tsl.is_none() => {
                    roots_warning = Some(format!("supplied roots.json: {e}"));
                    attempt(&config.roots).map(|ok| (ok, "embedded"))
                }
                other => other.map(|ok| (ok, "supplied")),
            },
            None => attempt(&config.roots).map(|ok| (ok, "embedded")),
        };
        let (store, tsl, listed) = match outcome {
            Ok(((store, verified), source)) => {
                let list = &verified.tsl;
                let listed = list
                    .services
                    .iter()
                    .filter_map(|s| s.certificate.as_ref())
                    .map(|c| fingerprint(c.der()))
                    .collect();
                let state = TslState {
                    result: "valid",
                    error: None,
                    sequence_number: Some(list.sequence_number),
                    next_update: list.next_update.map(|t| t.to_string()),
                    roots_source: source,
                    roots_warning,
                };
                (Some(Arc::new(store)), state, listed)
            }
            Err(e) => {
                let error = e.tsl.as_ref().map_or_else(
                    || Finding {
                        code: "roots_error",
                        code_number: None,
                        rule: "A_28419",
                        detail: e.reason.clone(),
                    },
                    Finding::from,
                );
                let state = TslState {
                    result: "invalid",
                    error: Some(error),
                    sequence_number: None,
                    next_update: None,
                    roots_source: "embedded",
                    roots_warning,
                };
                (None, state, HashSet::new())
            }
        };
        CheckContext {
            env,
            config,
            store,
            tsl,
            listed,
        }
    }

    /// The state of the trust material.
    pub fn tsl(&self) -> &TslState {
        &self.tsl
    }

    /// `certs`, the end entity first and any intermediates after it, checked at `now`.
    ///
    /// # Panics
    ///
    /// If `certs` is empty.
    pub fn check(&self, certs: &[Certificate], now: Timestamp) -> CheckReport {
        let ee = &certs[0];
        let mut report = CheckReport {
            schema: SCHEMA,
            environment: self.env.as_str(),
            result: "invalid",
            tsl: self.tsl.clone(),
            profile: None,
            certificate_type: None,
            errors: Vec::new(),
            warnings: Vec::new(),
            revocation: "not_checked",
            tree: Vec::new(),
            certificates: certs.iter().map(|c| describe(c, now)).collect(),
        };
        let Some(store) = &self.store else {
            report.errors.push(Issue {
                code: "tsl_invalid",
                subject: String::new(),
                message: "the TSL of this environment is not valid; nothing can be trusted"
                    .to_owned(),
            });
            report.tree = vec![self.node(ee, &ee_role(ee, None), now, false)];
            return report;
        };

        let selection = select_for_cert(ee);
        let mut validator =
            if let (Some(profile), Some(t)) = (selection.profile, selection.cert_type) {
                report.profile = Some(ProfileUsed {
                    name: profile.name,
                    reason: selection.reason.as_str(),
                    detail: selection.detail,
                });
                report.certificate_type = Some(t.to_string());
                profile.validator(&self.config, Arc::clone(store), t)
            } else {
                report.warnings.push(Issue {
                    code: "profile_not_detected",
                    subject: ee.subject_cn().to_owned(),
                    message: format!("{}; checked the chain only", selection.detail),
                });
                Validator::new(&self.config, Arc::clone(store))
            };
        validator.revocation = RevocationMode::Disabled;
        let result = match block_on(validator.validate(certs, now, &Unchecked)) {
            Ok(result) => result,
            Err(e) => {
                report.errors.push(Issue {
                    code: "malformed",
                    subject: ee.subject_cn().to_owned(),
                    message: e.to_string(),
                });
                report.tree = vec![self.node(ee, &ee_role(ee, None), now, false)];
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
        report.tree = self.tree(ee, &result, report.certificate_type.as_deref(), now);
        report
    }

    /// The chain as built, end entity first; a chain that reaches no trusted root ends in
    /// its missing issuer.
    fn tree(
        &self,
        ee: &Certificate,
        result: &ValidationResult,
        cert_type: Option<&str>,
        now: Timestamp,
    ) -> Vec<TrustNode> {
        let reaches_root = result.positions.last() == Some(&ChainPosition::Root);
        let chain: Cow<'_, [Certificate]> = if result.chain.is_empty() {
            Cow::Owned(vec![ee.clone()])
        } else {
            Cow::Borrowed(&result.chain)
        };
        let failed = |cert: &Certificate| {
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
                self.node(cert, &role, now, reaches_root && !failed(cert))
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

    fn node(&self, cert: &Certificate, role: &str, now: Timestamp, trusted: bool) -> TrustNode {
        let fp = fingerprint(cert.der());
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
            id: self.listed.contains(&fp).then_some(fp),
            name: name_of(cert.subject_cn(), &cert.subject().to_string()),
            role: role.to_owned(),
            note,
            state,
        }
    }
}

fn ee_role(cert: &Certificate, cert_type: Option<&str>) -> String {
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

fn name_of(cn: &str, dn: &str) -> String {
    if cn.is_empty() {
        dn.to_owned()
    } else {
        cn.to_owned()
    }
}

fn day(t: Timestamp) -> String {
    t.to_string()
        .split('T')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Runs ti-pki's async validation without a runtime: with revocation unchecked nothing in
/// it waits, so the future is complete when first polled.
fn block_on<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("validation without revocation never waits"),
    }
}
