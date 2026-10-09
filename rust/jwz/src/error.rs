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
