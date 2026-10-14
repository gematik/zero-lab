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

use alloc::borrow::Cow;
use core::fmt;

/// What kind of check failed; callers map it to their result code.
///
/// The kinds follow the result codes of `spec/tsl-xmldsig/README.md`: a document that is
/// not acceptable XML, a signature that fails the profile or the computation, and a signer
/// certificate that cannot be taken from `KeyInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input is not well-formed XML 1.0 in UTF-8, declares a DTD, or exceeds a limit
    /// (`tsl_not_wellformed`).
    NotWellFormed,
    /// The signature does not match the profile or does not verify
    /// (`xml_signature_error`).
    Signature,
    /// `KeyInfo` does not hold exactly one parsable signer certificate
    /// (`tsl_cert_extraction_error`).
    SignerCertificate,
}

/// A failed check: its kind, the specification rule it enforces and what exactly failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    rule: &'static str,
    detail: Cow<'static, str>,
}

impl Error {
    pub(crate) fn new(
        kind: ErrorKind,
        rule: &'static str,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Error {
            kind,
            rule,
            detail: detail.into(),
        }
    }

    pub(crate) fn not_well_formed(detail: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorKind::NotWellFormed, "TSLSIG-001", detail)
    }

    /// The kind of check that failed.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The identifier of the rule in `spec/tsl-xmldsig/README.md` that failed, e.g.
    /// `TSLSIG-013`.
    pub fn rule(&self) -> &'static str {
        self.rule
    }

    /// What failed, for humans; not stable.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.rule, self.detail)
    }
}

impl core::error::Error for Error {}
