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

//! The store: a backend and a sealer for the registered namespaces.

use ti_types::Timestamp;
use zeroize::Zeroizing;

use super::StoreError;
use super::backend::{Backend, Query, StoredRecord};
use super::names::{Field, Kid, Name, Namespace, Tag, plain_name, plain_tag};
use super::record::{open_plain, plain_record};
use super::registry::{Kind, NamespaceSpec};
use super::sealer::Sealer;

/// A record as the store hands it out.
#[derive(Debug)]
pub struct Stored {
    /// Its name.
    pub name: Name,
    /// Its payload, overwritten when dropped.
    pub payload: Zeroizing<Vec<u8>>,
    /// Its expiry.
    pub expires_at: Option<Timestamp>,
    /// The kid it was sealed under; none for a plain record.
    pub kid: Option<Kid>,
}

/// Records of registered namespaces in a [`Backend`], sealed by `S` where the namespace
/// says so (section B to F). Without a sealer, plain namespaces work and sealed ones are
/// refused (STORE-023).
#[derive(Debug)]
pub struct Store<B, S> {
    backend: B,
    sealer: Option<S>,
}

impl<B: Backend, S: Sealer> Store<B, S> {
    /// A store for `namespaces`, refused if the backend lacks a capability one of them
    /// requires (STORE-019).
    ///
    /// # Errors
    ///
    /// `capability_missing` if the backend lacks what a namespace requires.
    pub fn new(
        backend: B,
        sealer: Option<S>,
        namespaces: &[NamespaceSpec],
    ) -> Result<Self, StoreError> {
        let caps = backend.capabilities();
        for ns in namespaces {
            let r = ns.requires;
            for (needed, have, what) in [
                (r.atomic_take, caps.atomic_take, "atomic take"),
                (r.atomic_batch, caps.atomic_batch, "atomic batch"),
                (r.indexed, caps.indexed, "indexed queries"),
                (r.multi_process, caps.multi_process, "multi-process access"),
            ] {
                if needed && !have {
                    return Err(StoreError::CapabilityMissing(what));
                }
            }
        }
        Ok(Store { backend, sealer })
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn sealer(&self, spec: &NamespaceSpec) -> Result<Option<&S>, StoreError> {
        match spec.kind {
            Kind::Plain => Ok(None),
            Kind::Sealed => self.sealer.as_ref().map(Some).ok_or(StoreError::NoKeyring),
        }
    }

    fn namespace(spec: &NamespaceSpec) -> Result<Namespace, StoreError> {
        Namespace::new(spec.name)
    }

    fn name(&self, spec: &NamespaceSpec, ns: &Namespace, id: &[u8]) -> Result<Name, StoreError> {
        match self.sealer(spec)? {
            Some(s) => s.name(ns, id),
            None => plain_name(ns, id),
        }
    }

    fn tags(
        &self,
        spec: &NamespaceSpec,
        ns: &Namespace,
        metadata: &[(&str, &[u8])],
    ) -> Result<Vec<Tag>, StoreError> {
        metadata
            .iter()
            .map(|(field, value)| {
                if !spec.fields.contains(field) {
                    return Err(StoreError::InvalidArgument(
                        "field not indexed in this namespace",
                    ));
                }
                let field = Field::new(field)?;
                match self.sealer(spec)? {
                    Some(s) => s.tag(ns, &field, value),
                    None => plain_tag(ns, &field, value),
                }
            })
            .collect()
    }

    fn open(
        &self,
        spec: &NamespaceSpec,
        ns: &Namespace,
        name: Name,
        record: &StoredRecord,
        now: Timestamp,
    ) -> Result<Stored, StoreError> {
        let opened = match self.sealer(spec)? {
            Some(s) => s.open(ns, &name, now, &record.value)?,
            None => open_plain(now, &record.value)?,
        };
        Ok(Stored {
            name,
            payload: opened.payload,
            expires_at: opened.not_after,
            kid: opened.kid,
        })
    }

    /// Stores `payload` under `id` with indexed `metadata`, replacing what was there
    /// (STORE-011, STORE-022).
    ///
    /// # Errors
    ///
    /// `invalid_argument` for an expiry outside the namespace's lifetime or an
    /// unindexed field; `no_keyring` for a sealed namespace without a sealer; the sealer's and
    /// the backend's errors.
    pub async fn put(
        &self,
        spec: &NamespaceSpec,
        id: &[u8],
        payload: &[u8],
        metadata: &[(&str, &[u8])],
        expires_at: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<Name, StoreError> {
        // STORE-022: a namespace with a lifetime bounds every record.
        if spec.max_ttl != 0 {
            match expires_at {
                None => {
                    return Err(StoreError::InvalidArgument(
                        "record without expiry in a namespace with a lifetime",
                    ));
                }
                Some(t) if t.0 > now.0.saturating_add(spec.max_ttl) => {
                    return Err(StoreError::InvalidArgument(
                        "expiry beyond the namespace's lifetime",
                    ));
                }
                Some(_) => {}
            }
        }
        let ns = Self::namespace(spec)?;
        let name = self.name(spec, &ns, id)?;
        let tags = self.tags(spec, &ns, metadata)?;
        let value = match self.sealer(spec)? {
            Some(s) => s.seal(&ns, &name, expires_at, payload)?,
            None => plain_record(expires_at, payload)?,
        };
        self.backend
            .put(
                &ns,
                &name,
                StoredRecord {
                    value,
                    expires_at,
                    tags,
                },
            )
            .await?;
        Ok(name)
    }

    /// The live record under `id` (STORE-010, STORE-055).
    ///
    /// # Errors
    ///
    /// `not_found`; `no_keyring`; the sealer's and the backend's errors.
    pub async fn get(
        &self,
        spec: &NamespaceSpec,
        id: &[u8],
        now: Timestamp,
    ) -> Result<Stored, StoreError> {
        let ns = Self::namespace(spec)?;
        let name = self.name(spec, &ns, id)?;
        let record = self.backend.get(&ns, &name, now).await?;
        self.open(spec, &ns, name, &record, now)
    }

    /// Takes the live record under `id`: exactly one caller gets it (STORE-012).
    ///
    /// # Errors
    ///
    /// `capability_missing` without atomic take; otherwise as [`Store::get`].
    pub async fn take(
        &self,
        spec: &NamespaceSpec,
        id: &[u8],
        now: Timestamp,
    ) -> Result<Stored, StoreError> {
        if !self.backend.capabilities().atomic_take {
            return Err(StoreError::CapabilityMissing("atomic take"));
        }
        let ns = Self::namespace(spec)?;
        let name = self.name(spec, &ns, id)?;
        let record = self.backend.take(&ns, &name, now).await?;
        self.open(spec, &ns, name, &record, now)
    }

    /// Removes the record under `id` (STORE-013).
    ///
    /// # Errors
    ///
    /// `no_keyring`; the backend's errors.
    pub async fn delete(&self, spec: &NamespaceSpec, id: &[u8]) -> Result<(), StoreError> {
        let ns = Self::namespace(spec)?;
        let name = self.name(spec, &ns, id)?;
        self.backend.delete(&ns, &name).await
    }

    /// Live records whose metadata equals every `filters` value, one page at a time
    /// (STORE-015, STORE-016). A record that does not open fails the page.
    ///
    /// # Errors
    ///
    /// As [`Store::get`]; also `invalid_argument` for an unindexed field or a limit
    /// outside 1 to 1000.
    pub async fn query(
        &self,
        spec: &NamespaceSpec,
        filters: &[(&str, &[u8])],
        limit: usize,
        cursor: Option<Name>,
        now: Timestamp,
    ) -> Result<(Vec<Stored>, Option<Name>), StoreError> {
        let ns = Self::namespace(spec)?;
        let filters = self.tags(spec, &ns, filters)?;
        let page = self
            .backend
            .query(&Query {
                ns: ns.clone(),
                filters,
                from: None,
                to: None,
                limit,
                cursor,
                now,
            })
            .await?;
        let records = page
            .records
            .into_iter()
            .map(|(name, r)| self.open(spec, &ns, name, &r, now))
            .collect::<Result<_, _>>()?;
        Ok((records, page.cursor))
    }
}
