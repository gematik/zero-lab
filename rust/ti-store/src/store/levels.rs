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

//! Section K: format levels.

use super::StoreError;

/// The highest format level this implementation reads and writes.
pub const MAX_LEVEL: u16 = 1;

/// STORE-100: whether an implementation supporting levels up to `max` may open data at
/// `level` that needs `min_compatible`. A newer level opens as long as it stays compatible.
///
/// # Errors
///
/// `malformed` for levels out of order, `unsupported_version` if `min_compatible`
/// exceeds `max`.
pub fn check_open(max: u16, level: u16, min_compatible: u16) -> Result<(), StoreError> {
    if min_compatible < 1 || min_compatible > level {
        return Err(StoreError::Malformed("format level"));
    }
    if min_compatible > max {
        return Err(StoreError::UnsupportedVersion("format level"));
    }
    Ok(())
}

/// STORE-101: a database's `user_version` and `meta` must agree before STORE-100 applies.
///
/// # Errors
///
/// `malformed` if `user_version` and `level` differ; otherwise as [`check_open`].
pub fn check_database(
    max: u16,
    user_version: u16,
    level: u16,
    min_compatible: u16,
) -> Result<(), StoreError> {
    if user_version != level {
        return Err(StoreError::Malformed("format level"));
    }
    check_open(max, level, min_compatible)
}
