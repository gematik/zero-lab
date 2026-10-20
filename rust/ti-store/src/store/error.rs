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

//! The result codes of spec/store as one error type.

/// A store failure. Each variant is one result code of spec/store; [`StoreError::code`]
/// gives its name there.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No live record under that name.
    #[error("no such record")]
    NotFound,
    /// The record's `not_after` has passed.
    #[error("record expired")]
    Expired,
    /// A value, record, keyring, key file or database does not parse.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A version, wrapper or format level this implementation does not know.
    #[error("unsupported version of {0}")]
    UnsupportedVersion(&'static str),
    /// A record names a kid that is not in the keyring.
    #[error("record sealed under a key that is not in the keyring")]
    UnknownKid,
    /// A record or wrapped key does not authenticate under its context.
    #[error("{0} does not authenticate")]
    AuthFailed(&'static str),
    /// A size or count above its limit.
    #[error("{0} too large")]
    LimitExceeded(&'static str),
    /// A namespace, field, profile name, limit or lifetime outside its rule.
    #[error("invalid {0}")]
    InvalidArgument(&'static str),
    /// The backend lacks a capability a namespace requires.
    #[error("backend lacks {0}")]
    CapabilityMissing(&'static str),
    /// A sealed namespace was used without a keyring.
    #[error("no keyring")]
    NoKeyring,
    /// A key file readable by others.
    #[error("key file readable by others")]
    InsecurePermissions,
    /// The database stayed locked past the busy timeout.
    #[error("store busy")]
    Busy,
    /// An I/O or database error outside these rules.
    #[error("store backend: {0}")]
    Backend(String),
}

impl StoreError {
    /// The result code of spec/store.
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::NotFound => "not_found",
            StoreError::Expired => "expired",
            StoreError::Malformed(_) => "malformed",
            StoreError::UnsupportedVersion(_) => "unsupported_version",
            StoreError::UnknownKid => "unknown_kid",
            StoreError::AuthFailed(_) => "auth_failed",
            StoreError::LimitExceeded(_) => "limit_exceeded",
            StoreError::InvalidArgument(_) => "invalid_argument",
            StoreError::CapabilityMissing(_) => "capability_missing",
            StoreError::NoKeyring => "no_keyring",
            StoreError::InsecurePermissions => "insecure_permissions",
            StoreError::Busy => "busy",
            StoreError::Backend(_) => "backend_error",
        }
    }
}
