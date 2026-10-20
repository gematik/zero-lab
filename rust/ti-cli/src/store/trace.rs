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

//! `TI_STORE_TRACE=1` (STORE-130): one line per store operation on standard error, at the
//! tool's edge around the backend. A line holds the time, the operation, the namespace,
//! the first 8 bytes of the name, the result code and the duration; nothing else of a
//! record.

use std::fmt::Write as _;
use std::time::Instant;

use ti_store::store::{
    Backend, BatchOp, Capabilities, Name, Namespace, Page, Query, StoreError, StoredRecord,
};
use ti_types::Timestamp;

/// A backend that traces its operations when switched on.
#[derive(Debug)]
pub struct Traced<B> {
    inner: B,
    on: bool,
}

impl<B> Traced<B> {
    /// `inner`, traced if `TI_STORE_TRACE` is `1`.
    pub fn from_env(inner: B) -> Self {
        Traced {
            inner,
            on: std::env::var("TI_STORE_TRACE").is_ok_and(|v| v == "1"),
        }
    }

    fn line<T>(
        &self,
        op: &str,
        ns: Option<&Namespace>,
        name: Option<&Name>,
        start: Instant,
        result: &Result<T, StoreError>,
    ) {
        if !self.on {
            return;
        }
        let mut short = String::new();
        match name {
            Some(n) => n.0[..8].iter().for_each(|b| {
                let _ = write!(short, "{b:02x}");
            }),
            None => short.push('-'),
        }
        let code = match result {
            Ok(_) => "ok",
            Err(e) => e.code(),
        };
        crate::output::diagnostic(format_args!(
            "store {} {op} {} {short} {code} {:.1}ms",
            jiff::Timestamp::now(),
            ns.map_or("-", Namespace::as_str),
            start.elapsed().as_secs_f64() * 1000.0,
        ));
    }
}

impl<B: Backend> Backend for Traced<B> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let start = Instant::now();
        let r = self.inner.get(ns, name, now).await;
        self.line("get", Some(ns), Some(name), start, &r);
        r
    }

    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError> {
        let start = Instant::now();
        let r = self.inner.put(ns, name, record).await;
        self.line("put", Some(ns), Some(name), start, &r);
        r
    }

    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let start = Instant::now();
        let r = self.inner.take(ns, name, now).await;
        self.line("take", Some(ns), Some(name), start, &r);
        r
    }

    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        let start = Instant::now();
        let r = self.inner.delete(ns, name).await;
        self.line("delete", Some(ns), Some(name), start, &r);
        r
    }

    async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError> {
        let start = Instant::now();
        let r = self.inner.batch(ops).await;
        self.line("batch", None, None, start, &r);
        r
    }

    async fn query(&self, query: &Query) -> Result<Page, StoreError> {
        let start = Instant::now();
        let r = self.inner.query(query).await;
        self.line("query", Some(&query.ns), query.cursor.as_ref(), start, &r);
        r
    }

    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
        let start = Instant::now();
        let r = self.inner.cleanup(now, limit).await;
        self.line("cleanup", None, None, start, &r);
        r
    }
}
