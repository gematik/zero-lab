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

//! The crate's error: a stable [`ErrorCode`] and a fixed description of where it arose.
//! Neither ever contains key material or token contents (ADR 0001, auditability), so an
//! error can be logged as is.

use core::fmt;

use crate::crypto::CryptoError;

/// What went wrong, stable across releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The input is not valid JSON, or not the JSON structure expected.
    Json,
    /// A JSON object has the same member twice.
    DuplicateMember,
    /// A base64url value is padded, has characters outside the alphabet, or
    /// non-canonical trailing bits.
    Base64,
    /// A required member is absent.
    MissingMember,
    /// A member has the wrong type or form.
    InvalidMember,
    /// The `kty` is not one this library handles.
    UnsupportedKeyType,
    /// The `crv` is not registered, or not for this key type.
    UnknownCurve,
    /// A key component has the wrong length for its curve.
    KeyLength,
    /// The algorithm is not registered, or registered but not available.
    UnsupportedAlgorithm,
    /// The key does not fit the algorithm (type, curve, or its own `alg`).
    KeyMismatch,
    /// A private key operation on a key without its private part.
    MissingPrivateKey,
    /// A signature or authentication tag does not verify.
    VerificationFailed,
    /// The token is larger than the policy allows; checked before anything is decoded.
    TokenTooLarge,
    /// The token's structure is wrong (number of parts, header not an object).
    Malformed,
    /// The policy does not allow what the token uses (an algorithm, a header parameter).
    PolicyViolation,
    /// A `crit` header parameter is not understood, or `crit` itself is malformed
    /// (RFC 7515 §4.1.11).
    Critical,
    /// A JWT whose `exp` has passed, or whose `iat` is older than the policy allows.
    Expired,
    /// A JWT whose `nbf` or `iat` lies in the future.
    NotYetValid,
    /// A JWT claim has the wrong type or a value the policy does not accept.
    InvalidClaim,
    /// A cryptographic primitive failed.
    Crypto(CryptoError),
}

/// An error with its code and a fixed description of the step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    context: &'static str,
}

impl Error {
    pub(crate) const fn new(code: ErrorCode, context: &'static str) -> Self {
        Error { code, context }
    }

    /// The stable code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Where it arose, e.g. `jwk member "x"`; static text, never input data.
    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.context)
    }
}

impl core::error::Error for Error {}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        let code = if e == CryptoError::VerificationFailed {
            ErrorCode::VerificationFailed
        } else {
            ErrorCode::Crypto(e)
        };
        Error::new(code, "crypto backend")
    }
}
