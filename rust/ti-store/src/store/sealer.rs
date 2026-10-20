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

//! The seam between the store and its keys.

use ti_types::Timestamp;

use super::StoreError;
use super::names::{Field, Name, Namespace, Tag};
use super::record::Opened;

/// Turns ids into names, metadata into tags and payloads into sealed records, for one
/// profile (sections D to F). Keys stay behind it: [`Keyring`](super::Keyring) holds them
/// in memory, other implementations may keep them in hardware.
pub trait Sealer {
    /// The profile the records are bound to (STORE-061).
    fn profile_id(&self) -> &[u8; 16];
    /// STORE-031: the name of `id`.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for an id longer than 4096 bytes.
    fn name(&self, ns: &Namespace, id: &[u8]) -> Result<Name, StoreError>;
    /// STORE-034: the tag of a metadata value.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for a value longer than 4096 bytes.
    fn tag(&self, ns: &Namespace, field: &Field, value: &[u8]) -> Result<Tag, StoreError>;
    /// Section F: seals `payload` under the current kid with a fresh nonce.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for a payload above 16 MiB; the random source's errors.
    fn seal(
        &self,
        ns: &Namespace,
        name: &Name,
        not_after: Option<Timestamp>,
        payload: &[u8],
    ) -> Result<Vec<u8>, StoreError>;
    /// STORE-055: opens a sealed record.
    ///
    /// # Errors
    ///
    /// As [`open_sealed`](super::open_sealed).
    fn open(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
        record: &[u8],
    ) -> Result<Opened, StoreError>;
}
