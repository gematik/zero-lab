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

//! An in-process backend, for tests and for tools that keep nothing across runs.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use ti_types::Timestamp;

use super::StoreError;
use super::backend::{Backend, BatchOp, Capabilities, Page, Query, StoredRecord};
use super::names::{Name, Namespace};

type Records = BTreeMap<Namespace, BTreeMap<Name, StoredRecord>>;

/// Records in memory, lost with the process. Every operation holds one lock, so `take` and
/// `batch` are atomic within the process; there is no other process to share with.
#[derive(Debug, Default)]
pub struct MemoryBackend(Mutex<Records>);

impl MemoryBackend {
    /// An empty backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Records>, StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Backend("memory backend lock poisoned".into()))
    }
}

impl Backend for MemoryBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            atomic_take: true,
            atomic_batch: true,
            indexed: false,
            multi_process: false,
        }
    }

    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let records = self.lock()?;
        records
            .get(ns)
            .and_then(|m| m.get(name))
            .filter(|r| r.is_live(now))
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError> {
        record.check()?;
        self.lock()?
            .entry(ns.clone())
            .or_default()
            .insert(*name, record);
        Ok(())
    }

    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let mut records = self.lock()?;
        let m = records.get_mut(ns).ok_or(StoreError::NotFound)?;
        if !m.get(name).is_some_and(|r| r.is_live(now)) {
            return Err(StoreError::NotFound);
        }
        m.remove(name).ok_or(StoreError::NotFound)
    }

    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        if let Some(m) = self.lock()?.get_mut(ns) {
            m.remove(name);
        }
        Ok(())
    }

    async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError> {
        for op in &ops {
            if let BatchOp::Put(_, _, r) = op {
                r.check()?;
            }
        }
        let mut records = self.lock()?;
        for op in ops {
            match op {
                BatchOp::Put(ns, name, r) => {
                    records.entry(ns).or_default().insert(name, r);
                }
                BatchOp::Delete(ns, name) => {
                    if let Some(m) = records.get_mut(&ns) {
                        m.remove(&name);
                    }
                }
            }
        }
        Ok(())
    }

    async fn query(&self, q: &Query) -> Result<Page, StoreError> {
        q.check()?;
        let records = self.lock()?;
        let Some(m) = records.get(&q.ns) else {
            return Ok(Page::default());
        };
        let start = q
            .cursor
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let found: Vec<_> = m
            .range((start, std::ops::Bound::Unbounded))
            .filter(|(_, r)| r.is_live(q.now) && r.matches(q))
            .take(q.limit)
            .map(|(n, r)| (*n, r.clone()))
            .collect();
        Ok(Page::from_matches(found, q.limit))
    }

    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
        if limit == 0 {
            return Err(StoreError::InvalidArgument("limit"));
        }
        let mut records = self.lock()?;
        let mut removed = 0;
        for m in records.values_mut() {
            let expired: Vec<Name> = m
                .iter()
                .filter(|(_, r)| !r.is_live(now))
                .map(|(n, _)| *n)
                .take(limit - removed)
                .collect();
            for n in expired {
                m.remove(&n);
                removed += 1;
            }
            if removed == limit {
                break;
            }
        }
        Ok(removed)
    }
}
