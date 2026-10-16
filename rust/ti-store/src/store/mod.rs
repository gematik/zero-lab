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

//! The sealed store shared by the TI command-line tools, as specified in `spec/store`.
//!
//! - [`Backend`] keeps records as bytes with a namespace, a name, an expiry and tags; it
//!   never holds a key. [`MemoryBackend`] is the in-process one; files and SQLite are
//!   adapters of the tools.
//! - [`Keyring`] holds a profile's data keys, unwrapped through a [`KeyWrapper`], and is
//!   the [`Sealer`] that turns ids into names, metadata into tags and payloads into
//!   sealed records.
//! - [`Store`] puts the two together for the namespaces of the [`registry`].
//!
//! Time is a parameter everywhere; randomness comes from a [`Random`].

mod backend;
mod error;
pub mod files;
mod kek;
mod keyring;
pub mod levels;
mod memory;
mod names;
pub mod profile;
mod random;
mod record;
pub mod registry;
mod sealer;
#[allow(
    clippy::module_inception,
    reason = "the facade is the store of this module"
)]
mod store;
mod wire;

pub use backend::{Backend, BatchOp, Capabilities, Page, Query, StoredRecord};
pub use error::StoreError;
pub use kek::parse_kek_file;
pub use keyring::{KeyFileWrapper, KeyWrapper, Keyring, KeyringFile, WrappedKey};
pub use memory::MemoryBackend;
pub use names::{Field, Kid, Name, Namespace, Tag, plain_name, plain_tag};
#[cfg(feature = "test-util")]
pub use random::FixedRandom;
pub use random::{OsRandom, Random};
pub use record::{
    DataKey, DerivedKeys, MAX_TIME, Opened, derive, open_plain, open_sealed, plain_record,
    seal_record,
};
pub use sealer::Sealer;
pub use store::{Store, Stored};
