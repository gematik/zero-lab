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

//! Section B: what a backend stores and the operations it offers.

use std::sync::Arc;

use ti_types::Timestamp;

use super::StoreError;
use super::names::{MAX_TAGS, Name, Namespace, Tag};

/// STORE-018: what a backend guarantees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent guarantees of STORE-018"
)]
pub struct Capabilities {
    /// `take` is atomic across processes and implementations (STORE-012).
    pub atomic_take: bool,
    /// `batch` is all or nothing (STORE-014).
    pub atomic_batch: bool,
    /// Query cost does not grow with records outside the result.
    pub indexed: bool,
    /// Several processes may use the same files.
    pub multi_process: bool,
}

/// A record as a backend keeps it: opaque value, expiry and tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The sealed or plain record (section F).
    pub value: Vec<u8>,
    /// The expiry; `None` does not expire (STORE-002, STORE-053).
    pub expires_at: Option<Timestamp>,
    /// The blind-index tags.
    pub tags: Vec<Tag>,
}

impl StoredRecord {
    /// STORE-003.
    pub fn is_live(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }

    /// STORE-011, STORE-033: the checks every backend makes before it stores a record.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for more than 16 tags, `invalid_argument` for an expiry of 0.
    pub fn check(&self) -> Result<(), StoreError> {
        if self.tags.len() > MAX_TAGS {
            return Err(StoreError::LimitExceeded("tags"));
        }
        if self.expires_at == Some(Timestamp(0)) {
            return Err(StoreError::InvalidArgument("expiry"));
        }
        super::record::check_write_time(self.expires_at)?;
        Ok(())
    }

    /// STORE-015: whether the record carries every filter tag and its expiry is in range.
    pub fn matches(&self, q: &Query) -> bool {
        let in_range = match self.expires_at {
            // a record that does not expire counts as later than any time
            None => q.to.is_none(),
            Some(t) => q.from.is_none_or(|f| t >= f) && q.to.is_none_or(|e| t < e),
        };
        in_range && q.filters.iter().all(|f| self.tags.contains(f))
    }
}

/// STORE-015, STORE-016: a query.
#[derive(Clone, Debug)]
pub struct Query {
    /// The namespace.
    pub ns: Namespace,
    /// Tags every result carries.
    pub filters: Vec<Tag>,
    /// Lowest expiry, inclusive.
    pub from: Option<Timestamp>,
    /// Highest expiry, exclusive.
    pub to: Option<Timestamp>,
    /// At most this many records, 1 to 1000.
    pub limit: usize,
    /// Only names strictly greater than this.
    pub cursor: Option<Name>,
    /// The time that decides what is live.
    pub now: Timestamp,
}

impl Query {
    /// STORE-016: the limit's range.
    ///
    /// # Errors
    ///
    /// `invalid_argument` for a limit outside 1 to 1000.
    pub fn check(&self) -> Result<(), StoreError> {
        if (1..=1000).contains(&self.limit) {
            Ok(())
        } else {
            Err(StoreError::InvalidArgument("limit"))
        }
    }
}

/// One page of a query.
#[derive(Clone, Debug, Default)]
pub struct Page {
    /// Records in ascending order of name.
    pub records: Vec<(Name, StoredRecord)>,
    /// Set when the page is full: pass it as the next query's cursor.
    pub cursor: Option<Name>,
}

impl Page {
    /// STORE-016: a page from the first `limit` matches, with a cursor exactly when it is
    /// full.
    pub fn from_matches(records: Vec<(Name, StoredRecord)>, limit: usize) -> Self {
        let cursor = (records.len() == limit)
            .then(|| records.last().map(|(n, _)| *n))
            .flatten();
        Page { records, cursor }
    }
}

/// One operation of a batch.
#[derive(Clone, Debug)]
pub enum BatchOp {
    /// Store a record.
    Put(Namespace, Name, StoredRecord),
    /// Remove a record.
    Delete(Namespace, Name),
}

/// Keeps records (section B). Asynchronous so that a backend may do I/O; without `Send`
/// bounds so that it builds for wasm32.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Backend {
    /// STORE-018.
    fn capabilities(&self) -> Capabilities;
    /// STORE-010.
    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError>;
    /// STORE-011.
    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError>;
    /// STORE-012.
    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError>;
    /// STORE-013.
    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError>;
    /// STORE-014.
    async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError>;
    /// STORE-015, STORE-016.
    async fn query(&self, query: &Query) -> Result<Page, StoreError>;
    /// STORE-017.
    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError>;
}

macro_rules! forward {
    ($ty:ty) => {
        impl<B: Backend + ?Sized> Backend for $ty {
            fn capabilities(&self) -> Capabilities {
                (**self).capabilities()
            }
            async fn get(
                &self,
                ns: &Namespace,
                name: &Name,
                now: Timestamp,
            ) -> Result<StoredRecord, StoreError> {
                (**self).get(ns, name, now).await
            }
            async fn put(
                &self,
                ns: &Namespace,
                name: &Name,
                record: StoredRecord,
            ) -> Result<(), StoreError> {
                (**self).put(ns, name, record).await
            }
            async fn take(
                &self,
                ns: &Namespace,
                name: &Name,
                now: Timestamp,
            ) -> Result<StoredRecord, StoreError> {
                (**self).take(ns, name, now).await
            }
            async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
                (**self).delete(ns, name).await
            }
            async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError> {
                (**self).batch(ops).await
            }
            async fn query(&self, query: &Query) -> Result<Page, StoreError> {
                (**self).query(query).await
            }
            async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
                (**self).cleanup(now, limit).await
            }
        }
    };
}

forward!(&B);
forward!(Arc<B>);
