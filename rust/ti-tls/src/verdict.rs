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

//! The result codes of `spec/pki-validation` and the verdict both profiles return.

use core::fmt;

/// A result code of `spec/pki-validation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The server may be trusted.
    Valid,
    /// TLSV-033.
    TrustMaterialUnavailable,
    /// TLSV-020.
    ChainIncomplete,
    /// TLSV-021.
    NotYetValid,
    /// TLSV-021.
    Expired,
    /// TLSV-022.
    KeyUsageMismatch,
    /// TLSV-023.
    SignatureAlgorithmNotAllowed,
    /// TLSV-023.
    SignatureInvalid,
    /// TLSV-024, TLSV-031, TLSV-043.
    NameMismatch,
    /// TLSV-030.
    ProfileTypeMismatch,
    /// TLSV-030, TLSV-041, TLSV-042.
    KeyNotAdmissible,
    /// PATH-004.
    UnrecognizedCriticalExtension,
    /// VALID-006.
    CaNotInTsl,
    /// VALID-007.
    CertTypeCaNotAuthorized,
    /// VALID-003.
    CaRevokedInTsl,
    /// TLSV-032.
    OcspRevoked,
    /// TLSV-032.
    OcspUnknown,
    /// TLSV-032.
    OcspUnavailable,
    /// TLSV-032.
    OcspResponseInvalid,
    /// TLSV-044.
    Revoked,
    /// TLSV-044 before its deviation; the `web` profile now accepts such a server with the
    /// warning [`REVOCATION_UNAVAILABLE`] and returns this code no more.
    RevocationUnavailable,
    /// TLSV-045.
    ValidityTooLong,
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
            Code::NameMismatch => "name_mismatch",
            Code::ProfileTypeMismatch => "profile_type_mismatch",
            Code::KeyNotAdmissible => "key_not_admissible",
            Code::UnrecognizedCriticalExtension => "unrecognized_critical_extension",
            Code::CaNotInTsl => "ca_not_in_tsl",
            Code::CertTypeCaNotAuthorized => "cert_type_ca_not_authorized",
            Code::CaRevokedInTsl => "ca_revoked_in_tsl",
            Code::OcspRevoked => "ocsp_revoked",
            Code::OcspUnknown => "ocsp_unknown",
            Code::OcspUnavailable => "ocsp_unavailable",
            Code::OcspResponseInvalid => "ocsp_response_invalid",
            Code::Revoked => "revoked",
            Code::RevocationUnavailable => "revocation_unavailable",
            Code::ValidityTooLong => "validity_too_long",
            Code::Invalid => "invalid",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ti_pki::tls::Code> for Code {
    fn from(code: ti_pki::tls::Code) -> Code {
        use ti_pki::tls::Code as Ti;
        match code {
            Ti::Valid => Code::Valid,
            Ti::TrustMaterialUnavailable => Code::TrustMaterialUnavailable,
            Ti::ChainIncomplete => Code::ChainIncomplete,
            Ti::NotYetValid => Code::NotYetValid,
            Ti::Expired => Code::Expired,
            Ti::KeyUsageMismatch => Code::KeyUsageMismatch,
            Ti::SignatureAlgorithmNotAllowed => Code::SignatureAlgorithmNotAllowed,
            Ti::SignatureInvalid => Code::SignatureInvalid,
            Ti::ProfileTypeMismatch => Code::ProfileTypeMismatch,
            Ti::KeyNotAdmissible => Code::KeyNotAdmissible,
            Ti::UnrecognizedCriticalExtension => Code::UnrecognizedCriticalExtension,
            Ti::CaNotInTsl => Code::CaNotInTsl,
            Ti::CertTypeCaNotAuthorized => Code::CertTypeCaNotAuthorized,
            Ti::CaRevokedInTsl => Code::CaRevokedInTsl,
            Ti::NameMismatch => Code::NameMismatch,
            Ti::OcspRevoked => Code::OcspRevoked,
            Ti::OcspUnknown => Code::OcspUnknown,
            Ti::OcspUnavailable => Code::OcspUnavailable,
            Ti::OcspResponseInvalid => Code::OcspResponseInvalid,
            _ => Code::Invalid,
        }
    }
}

/// TLSV-041: an end-entity RSA key of 2048 to 2999 bits, accepted under `web` though
/// below A_28976's 3000 (the spec's deviation); ti-pki gives the same key the same code.
pub const KEY_PHASED_OUT: &str = "key_phased_out";

/// TLSV-044: no source gave the end entity's revocation status, and the `web` server was
/// accepted without one (the spec's deviation from A_27857-02).
pub const REVOCATION_UNAVAILABLE: &str = "revocation_unavailable";

/// Where the revocation status an accepted `web` verdict rests on came from (TLSV-044).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusSource {
    /// The OCSP response the server stapled.
    Stapled,
    /// The end entity's OCSP responder (AIA).
    Responder,
    /// The end entity's CRL distribution point.
    Crl,
}

impl StatusSource {
    /// `stapled_ocsp`, `ocsp_responder` or `crl`.
    pub const fn as_str(self) -> &'static str {
        match self {
            StatusSource::Stapled => "stapled_ocsp",
            StatusSource::Responder => "ocsp_responder",
            StatusSource::Crl => "crl",
        }
    }
}

impl fmt::Display for StatusSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a check concluded about a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The result code; [`Code::Valid`] when the server may be trusted.
    pub code: Code,
    /// Why, in words.
    pub detail: String,
    /// Warnings, which never decide.
    pub warnings: Vec<&'static str>,
    /// Under `web`, the source of the revocation status the verdict rests on; `None` under
    /// `ti`, for a refusal before revocation, and with [`REVOCATION_UNAVAILABLE`].
    pub status_source: Option<StatusSource>,
    /// Until when, in seconds since the epoch, an accepted verdict may be reused
    /// (TLSV-050, TLSV-051); `None` for a refusal, which is never reused.
    pub reusable_until: Option<u64>,
}

impl Verdict {
    /// Whether the server may be trusted.
    pub fn is_valid(&self) -> bool {
        self.code == Code::Valid
    }

    pub(crate) fn refuse(code: Code, detail: impl Into<String>) -> Verdict {
        Verdict {
            code,
            detail: detail.into(),
            warnings: Vec::new(),
            status_source: None,
            reusable_until: None,
        }
    }
}
