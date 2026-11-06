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

//! A TLS server of the TI, judged under the `ti` profile of `spec/pki-validation`: the
//! certificate checks a client makes before it sends anything (GS-A_4662), independent of
//! the TLS library that carries the handshake. The library's adapter (`ti-tls`) hands over
//! the chain, the host name and a stapled OCSP response, and acts on the verdict.

use core::fmt;
use core::time::Duration;
use std::net::IpAddr;
use std::sync::Arc;

use const_oid::ObjectIdentifier;

use crate::cert_type::detect_certificate_type;
use crate::ocsp::{ResponseCheck, verify_response};
use crate::revocation::{RevocationChecker, RevocationMode, RevocationStatus};
use crate::{
    Certificate, CertificateType, ErrorCode, Timestamp, TrustConfig, TrustStore, ValidationError,
    Validator,
};

/// TUC_PKI_018's default OCSP grace period: how long after a response the reference time may
/// lie for a stapled response to count (TLSV-032).
pub const DEFAULT_OCSP_GRACE: Duration = Duration::from_mins(10);

/// The types of Tab_PKI_405 a TLS server presents (TLSV-030).
pub const SERVER_TYPES: [CertificateType; 2] = [CertificateType::FdTlsS, CertificateType::ZdTlsS];

/// The result codes of `spec/pki-validation` the `ti` profile reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The server may be trusted.
    Valid,
    /// TLSV-033: no TSL within its grace period, so no trust store.
    TrustMaterialUnavailable,
    /// TLSV-020: no path to an anchor.
    ChainIncomplete,
    /// TLSV-021.
    NotYetValid,
    /// TLSV-021.
    Expired,
    /// TLSV-022.
    KeyUsageMismatch,
    /// TLSV-023: SHA-1, MD5 or SHA-224 in the path.
    SignatureAlgorithmNotAllowed,
    /// TLSV-023.
    SignatureInvalid,
    /// TLSV-030: not a TLS server type.
    ProfileTypeMismatch,
    /// TLSV-030 (VALID-002).
    KeyNotAdmissible,
    /// PATH-004.
    UnrecognizedCriticalExtension,
    /// VALID-006.
    CaNotInTsl,
    /// VALID-007.
    CertTypeCaNotAuthorized,
    /// VALID-003.
    CaRevokedInTsl,
    /// TLSV-031.
    NameMismatch,
    /// TLSV-032.
    OcspRevoked,
    /// TLSV-032.
    OcspUnknown,
    /// TLSV-032: no responder answered.
    OcspUnavailable,
    /// TLSV-032, OCSP-001: an answer that does not verify or is not authorized.
    OcspResponseInvalid,
    /// A finding the spec has no code of its own for.
    Invalid,
}

impl Code {
    /// The spec's snake_case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::Valid => "valid",
            Code::TrustMaterialUnavailable => "trust_material_unavailable",
            Code::ChainIncomplete => "chain_incomplete",
            Code::NotYetValid => "not_yet_valid",
            Code::Expired => "expired",
            Code::KeyUsageMismatch => "key_usage_mismatch",
            Code::SignatureAlgorithmNotAllowed => "signature_algorithm_not_allowed",
            Code::SignatureInvalid => "signature_invalid",
            Code::ProfileTypeMismatch => "profile_type_mismatch",
            Code::KeyNotAdmissible => "key_not_admissible",
            Code::UnrecognizedCriticalExtension => "unrecognized_critical_extension",
            Code::CaNotInTsl => "ca_not_in_tsl",
            Code::CertTypeCaNotAuthorized => "cert_type_ca_not_authorized",
            Code::CaRevokedInTsl => "ca_revoked_in_tsl",
            Code::NameMismatch => "name_mismatch",
            Code::OcspRevoked => "ocsp_revoked",
            Code::OcspUnknown => "ocsp_unknown",
            Code::OcspUnavailable => "ocsp_unavailable",
            Code::OcspResponseInvalid => "ocsp_response_invalid",
            Code::Invalid => "invalid",
        }
    }

    fn from_error(code: ErrorCode) -> Code {
        match code {
            ErrorCode::ChainIncomplete => Code::ChainIncomplete,
            ErrorCode::NotYetValid => Code::NotYetValid,
            ErrorCode::Expired => Code::Expired,
            ErrorCode::KeyUsageMismatch => Code::KeyUsageMismatch,
            ErrorCode::SignatureInvalid => Code::SignatureInvalid,
            ErrorCode::ProfileTypeMismatch
            | ErrorCode::ProfileNotDetected
            | ErrorCode::PolicyMismatch => Code::ProfileTypeMismatch,
            ErrorCode::KeyNotAdmissible => Code::KeyNotAdmissible,
            ErrorCode::UnrecognizedCriticalExtension => Code::UnrecognizedCriticalExtension,
            ErrorCode::CaNotInTsl => Code::CaNotInTsl,
            ErrorCode::CertTypeCaNotAuthorized => Code::CertTypeCaNotAuthorized,
            ErrorCode::CaRevokedInTsl => Code::CaRevokedInTsl,
            ErrorCode::OcspUnavailable => Code::OcspUnavailable,
            ErrorCode::OcspResponseInvalid | ErrorCode::OcspResponderUntrusted => {
                Code::OcspResponseInvalid
            }
            _ => Code::Invalid,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TLSV-032's warning: the stapled response did not hold, and the responder was asked.
pub const PROVIDED_OCSP_RESPONSE_NOT_VALID: &str = "provided_ocsp_response_not_valid";

/// What [`ServerCheck::verify`] concluded.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// The result code; [`Code::Valid`] when the server may be trusted.
    pub code: Code,
    /// Why, in words.
    pub detail: String,
    /// Warnings, which never decide.
    pub warnings: Vec<&'static str>,
    /// The end entity's `notAfter`: no accepted verdict outlives it (TLSV-050).
    pub not_after: Option<Timestamp>,
    /// When the OCSP status it rests on was produced: an accepted verdict lives at most
    /// OCSP-005's hour past it (TLSV-051).
    pub status_produced: Option<Timestamp>,
}

impl Verdict {
    /// Whether the server may be trusted.
    pub fn is_valid(&self) -> bool {
        self.code == Code::Valid
    }

    fn refuse(code: Code, detail: impl Into<String>, warnings: Vec<&'static str>) -> Verdict {
        Verdict {
            code,
            detail: detail.into(),
            warnings,
            not_after: None,
            status_produced: None,
        }
    }
}

/// The `ti` profile over one snapshot of the TI's trust material.
#[derive(Clone, Debug)]
pub struct ServerCheck {
    config: TrustConfig,
    store: Option<Arc<TrustStore>>,
    ocsp_grace: Duration,
}

impl ServerCheck {
    /// The check under `config`, with `store` the roots and verified TSL's CAs, or `None`
    /// while no TSL is within its grace period (TLSV-033).
    pub fn new(config: TrustConfig, store: Option<Arc<TrustStore>>) -> ServerCheck {
        ServerCheck {
            config,
            store,
            ocsp_grace: DEFAULT_OCSP_GRACE,
        }
    }

    /// The check with another OCSP grace period (Tab_PKI_273: configurable).
    #[must_use]
    pub fn with_ocsp_grace(mut self, grace: Duration) -> ServerCheck {
        self.ocsp_grace = grace;
        self
    }

    /// The trust store the verdicts rest on.
    pub fn store(&self) -> Option<&Arc<TrustStore>> {
        self.store.as_ref()
    }

    /// Judges the server that presented `chain` (end entity first) for a connection to
    /// `host`, at `now`, with the OCSP response it stapled. `responder` is asked only when
    /// no stapled response holds, and only about a server that passed everything else.
    pub async fn verify(
        &self,
        chain: &[Certificate],
        host: &str,
        stapled: Option<&[u8]>,
        now: Timestamp,
        responder: &impl RevocationChecker,
    ) -> Verdict {
        let Some(store) = &self.store else {
            return Verdict::refuse(
                Code::TrustMaterialUnavailable,
                "no TSL within its grace period (GS-A_5336)",
                Vec::new(),
            );
        };
        let Some(leaf) = chain.first() else {
            return Verdict::refuse(
                Code::ChainIncomplete,
                "the server sent no certificate",
                Vec::new(),
            );
        };
        let detected = detect_certificate_type(leaf);
        let mut validator = Validator::new(&self.config, Arc::clone(store));
        if let Some(t) = detected.filter(|t| SERVER_TYPES.contains(t)) {
            validator = validator.with_type_baseline(t);
        }
        validator.accepted_types = SERVER_TYPES.to_vec();
        // Revocation comes last, from the stapled response or the responder (TLSV-032).
        validator.revocation = RevocationMode::Disabled;
        let result = match validator
            .validate(chain, now, &crate::revocation::Unchecked)
            .await
        {
            Ok(result) => result,
            Err(e) => return Verdict::refuse(Code::ChainIncomplete, e.to_string(), Vec::new()),
        };
        if result.chain.len() < 2 {
            return refusal(&result.errors, Code::ChainIncomplete);
        }
        if let Some(weak) = result.chain[..result.chain.len() - 1]
            .iter()
            .find(|c| WEAK_SIGNATURES.contains(&c.inner().signature_algorithm().oid))
        {
            return Verdict::refuse(
                Code::SignatureAlgorithmNotAllowed,
                format!(
                    "{} is signed with {}",
                    weak.subject_cn(),
                    weak.signature_algorithm()
                ),
                Vec::new(),
            );
        }
        if !result.valid {
            return refusal(&result.errors, Code::Invalid);
        }
        if !names_host(leaf, host) {
            return Verdict::refuse(
                Code::NameMismatch,
                format!("{} does not name {host}", leaf.subject_cn()),
                Vec::new(),
            );
        }
        let issuer = &result.chain[1];
        let mut warnings = Vec::new();
        if let Some(der) = stapled {
            let check = ResponseCheck {
                max_response_age: self.ocsp_grace,
                store: Some(store),
                ..ResponseCheck::new(now, &self.config.algorithms)
            };
            // An answer outside the grace period comes back as Unknown with the reason; it is
            // no answer, and the responder is asked as if nothing had been stapled.
            match verify_response(der, leaf, issuer, &check) {
                Ok(status) if holds(&status, now, self.ocsp_grace) => {
                    return status_verdict(&status, leaf, warnings);
                }
                Ok(_) | Err(_) => warnings.push(PROVIDED_OCSP_RESPONSE_NOT_VALID),
            }
        }
        match responder.check(leaf, issuer, store).await {
            Ok(status) => status_verdict(&status, leaf, warnings),
            Err(e) => Verdict::refuse(Code::from_error(e.code), e.message, warnings),
        }
    }
}

/// TLSV-023: SHA-1, MD5 and SHA-224, with RSA and with ECDSA.
const WEAK_SIGNATURES: [ObjectIdentifier; 5] = [
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"),
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4"),
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14"),
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.1"),
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1"),
];

/// Whether a verified stapled `status` is an answer at `now`: a good or revoked status, or
/// an unknown one produced within `grace`.
fn holds(status: &crate::RevocationResult, now: Timestamp, grace: Duration) -> bool {
    status.status != RevocationStatus::Unknown
        || status
            .produced_at
            .is_some_and(|produced| produced <= now && now.since(produced) <= grace)
}

fn refusal(errors: &[ValidationError], fallback: Code) -> Verdict {
    match errors.first() {
        Some(e) => Verdict::refuse(Code::from_error(e.code), e.message.clone(), Vec::new()),
        None => Verdict::refuse(fallback, "invalid", Vec::new()),
    }
}

fn status_verdict(
    status: &crate::RevocationResult,
    leaf: &Certificate,
    warnings: Vec<&'static str>,
) -> Verdict {
    let code = match status.status {
        RevocationStatus::Good => Code::Valid,
        RevocationStatus::Revoked => Code::OcspRevoked,
        RevocationStatus::Unknown => Code::OcspUnknown,
    };
    Verdict {
        code,
        detail: format!("OCSP: {:?}", status.status),
        warnings,
        not_after: Some(leaf.not_after()),
        status_produced: status.produced_at,
    }
}

/// TLSV-024, TLSV-031: whether `cert` names `host` in its commonName or a `dNSName`, or, for
/// an IP address, an `iPAddress` subject alternative name.
pub fn names_host(cert: &Certificate, host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let alt_names = cert.subject_alt_names();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return alt_names
            .iter()
            .filter_map(|name| name.strip_prefix("IP:"))
            .any(|named| named.parse::<IpAddr>() == Ok(ip));
    }
    core::iter::once(cert.subject_cn())
        .chain(
            alt_names
                .iter()
                .filter_map(|name| name.strip_prefix("DNS:")),
        )
        .any(|presented| dns_name_matches(presented, host))
}

/// TLSV-024: `presented` against the reference `host`, case-insensitively in ASCII; a
/// wildcard is `*` as the whole leftmost label and stands for exactly one label.
pub fn dns_name_matches(presented: &str, host: &str) -> bool {
    let presented = presented.strip_suffix('.').unwrap_or(presented);
    if presented.is_empty() || !presented.is_ascii() || !host.is_ascii() {
        return false;
    }
    match presented.strip_prefix("*.") {
        Some(rest) => {
            if rest.contains('*') || rest.split('.').count() < 2 {
                return false;
            }
            match host.split_once('.') {
                Some((first, parent)) => !first.is_empty() && parent.eq_ignore_ascii_case(rest),
                None => false,
            }
        }
        None => !presented.contains('*') && presented.eq_ignore_ascii_case(host),
    }
}

#[cfg(test)]
mod tests {
    use super::dns_name_matches;

    /// TLSV-024: case-insensitive, without a trailing dot; a wildcard is the whole leftmost
    /// label and stands for exactly one label.
    #[test]
    fn tlsv_024_names_match_exactly_or_by_one_leftmost_wildcard_label() {
        for (presented, host) in [
            ("svc.ti.test", "svc.ti.test"),
            ("SVC.ti.test", "svc.TI.test"),
            ("svc.ti.test.", "svc.ti.test"),
            ("*.ti.test", "a.ti.test"),
            ("*.ti.test", "A.TI.TEST"),
        ] {
            assert!(dns_name_matches(presented, host), "{presented} {host}");
        }
        for (presented, host) in [
            ("svc.ti.test", "other.ti.test"),
            ("*.ti.test", "ti.test"),
            ("*.ti.test", "a.b.ti.test"),
            ("*.ti.test", ".ti.test"),
            ("f*.ti.test", "foo.ti.test"),
            ("a.*.test", "a.b.test"),
            ("*.*.test", "a.b.test"),
            ("*.test", "a.test"),
            ("*", "test"),
            ("", ""),
            ("svc.ti.test", "svc.ti.test.evil"),
            ("bücher.test", "bücher.test"),
        ] {
            assert!(!dns_name_matches(presented, host), "{presented} {host}");
        }
    }
}
