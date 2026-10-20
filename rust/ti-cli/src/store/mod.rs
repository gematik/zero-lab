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

//! The backends of ti's sealed store (spec/store): SQLite by default, files on request
//! (`TI_STORE_BACKEND=files`, STORE-131). The store itself, its keyring and its rules
//! are ti-store's; what does I/O is this tool's.

mod cache;
mod files;
pub mod profile;
mod sqlite;
#[cfg(test)]
mod tests;
mod trace;

use std::path::Path;

use ti_store::store::{
    Backend, BatchOp, Capabilities, Name, Namespace, Page, Query, StoreError, StoredRecord,
};
use ti_types::Timestamp;

pub use cache::StoreCache;
pub use files::FilesBackend;
pub use profile::now;
pub use trace::Traced;

/// The cache of the profile in effect.
///
/// # Errors
///
/// A profile that does not resolve, or a cache that cannot be created.
pub fn open_cache(global: &crate::cli::GlobalArgs) -> Result<StoreCache, crate::error::CliError> {
    profile::Selected::resolve(global)?
        .open_cache()
        .map(StoreCache)
}
pub use sqlite::{Db, SqliteBackend};

/// Which backend keeps a profile's records (STORE-131).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// `state.db` and `cache.db`.
    #[default]
    Sqlite,
    /// The `state` and `cache` trees, one file per record.
    Files,
}

impl Kind {
    /// `TI_STORE_BACKEND`: unset or empty is SQLite.
    ///
    /// # Errors
    ///
    /// `invalid_argument` for any value but `sqlite` and `files`.
    pub fn from_env(value: Option<&str>) -> Result<Self, StoreError> {
        match value {
            None | Some("" | "sqlite") => Ok(Kind::Sqlite),
            Some("files") => Ok(Kind::Files),
            Some(_) => Err(StoreError::InvalidArgument("TI_STORE_BACKEND")),
        }
    }
}

/// One of a profile's two stores, on the backend in effect.
#[derive(Debug)]
pub enum AnyBackend {
    /// A database file.
    Sqlite(SqliteBackend),
    /// A files tree.
    Files(FilesBackend),
}

impl AnyBackend {
    /// Opens `<path>` as the database (`state.db`, `cache.db`) or as the root of the files
    /// tree, by `kind`.
    ///
    /// # Errors
    ///
    /// As [`SqliteBackend::open`] and [`FilesBackend::open`].
    pub fn open(kind: Kind, path: &Path, db: Db) -> Result<Self, StoreError> {
        Ok(match kind {
            Kind::Sqlite => AnyBackend::Sqlite(SqliteBackend::open(path, db)?),
            Kind::Files => AnyBackend::Files(FilesBackend::open(path)?),
        })
    }
}

/// What `store doctor` reads of a database or files tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// The format level of its contents.
    pub level: u16,
    /// The lowest level a reader must support.
    pub min_compatible: u16,
    /// `PRAGMA quick_check`'s answer; none for a files tree.
    pub integrity: Option<String>,
}

/// How often a tool cleans up on its own, and how much at a time (STORE-125).
const DAILY: u64 = 86_400;
const DAILY_LIMIT: usize = 1000;

impl AnyBackend {
    /// Gives freed space back to the file system; nothing for a files tree.
    ///
    /// # Errors
    ///
    /// The database's errors.
    pub fn vacuum(&self) -> Result<(), StoreError> {
        match self {
            AnyBackend::Sqlite(b) => b.vacuum(),
            AnyBackend::Files(_) => Ok(()),
        }
    }

    /// Records that cleanup ran at `at`.
    ///
    /// # Errors
    ///
    /// The backend's errors.
    pub fn set_last_cleanup(&self, at: Timestamp) -> Result<(), StoreError> {
        match self {
            AnyBackend::Sqlite(b) => b.set_last_cleanup(at),
            AnyBackend::Files(b) => b.set_last_cleanup(at),
        }
    }

    /// STORE-125: removes up to 1000 expired records if the last such run is a day old
    /// or more, and records the time. Housekeeping: a failure only means it runs next
    /// time.
    pub fn daily_cleanup(&self, now: Timestamp) {
        let last = match self {
            AnyBackend::Sqlite(b) => b.last_cleanup().ok().flatten(),
            AnyBackend::Files(b) => b.last_cleanup(),
        };
        if last.is_some_and(|t| now.0.saturating_sub(t.0) < DAILY) {
            return;
        }
        if crate::block::block_on(self.cleanup(now, DAILY_LIMIT)).is_ok() {
            let _ = self.set_last_cleanup(now);
        }
    }

    /// Levels and integrity (STORE-123).
    ///
    /// # Errors
    ///
    /// The backend's errors.
    pub fn inspect(&self) -> Result<Inspection, StoreError> {
        match self {
            AnyBackend::Sqlite(b) => b.inspect(),
            AnyBackend::Files(b) => b.inspect(),
        }
    }
}

macro_rules! each {
    ($self:ident, $b:ident => $e:expr) => {
        match $self {
            AnyBackend::Sqlite($b) => $e,
            AnyBackend::Files($b) => $e,
        }
    };
}

impl Backend for AnyBackend {
    fn capabilities(&self) -> Capabilities {
        each!(self, b => b.capabilities())
    }
    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        each!(self, b => b.get(ns, name, now).await)
    }
    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError> {
        each!(self, b => b.put(ns, name, record).await)
    }
    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        each!(self, b => b.take(ns, name, now).await)
    }
    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        each!(self, b => b.delete(ns, name).await)
    }
    async fn batch(&self, ops: Vec<BatchOp>) -> Result<(), StoreError> {
        each!(self, b => b.batch(ops).await)
    }
    async fn query(&self, query: &Query) -> Result<Page, StoreError> {
        each!(self, b => b.query(query).await)
    }
    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
        each!(self, b => b.cleanup(now, limit).await)
    }
}
