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

//! JSON Web Algorithms: the names of algorithms, curves and key types, and the
//! [`Registry`] that says what each name means.
//!
//! A name is an interned `&'static str` in a typed [`Name`]: [`SignatureAlgorithm`],
//! [`KeyEncryptionAlgorithm`], [`ContentEncryptionAlgorithm`], [`Curve`] or [`KeyType`].
//! Names are open: any crate can define one with `Name::new`, and a [`Registry`]
//! decides which names a program knows. [`Registry::standard`] holds RFC 7518 and
//! RFC 8037; an extension crate adds its own.
//! This module holds no cryptography and depends on nothing else in the crate.
//!
//! The registry is a value, not a global: every parse is given the registry and the
//! policy it runs under, so what a program accepts is visible where it parses.
//!
//! # Registering an algorithm from another crate
//!
//! `jwz-brainpool` registers gematik's brainpool signature algorithm like this:
//!
//! ```
//! use jwz::jwa::{
//!     Curve, CurveEntry, HashAlgorithm, KeyType, Registry, SignatureAlgorithm,
//!     SignatureEntry, Support,
//! };
//!
//! const BP256R1: SignatureAlgorithm = SignatureAlgorithm::new("BP256R1");
//! const BP_256: Curve = Curve::new("BP-256");
//!
//! let mut registry = Registry::standard();
//! registry.register_curve(CurveEntry {
//!     crv: BP_256,
//!     key_type: KeyType::EC,
//!     coordinate_len: 32,
//!     support: Support::Available,
//! })?;
//! registry.register_signature(SignatureEntry {
//!     alg: BP256R1,
//!     key_type: KeyType::EC,
//!     curve: Some(BP_256),
//!     hash: Some(HashAlgorithm::Sha256),
//!     support: Support::Available,
//! })?;
//! assert_eq!(registry.signature("BP256R1").map(|e| e.curve), Some(Some(BP_256)));
//! # Ok::<(), jwz::jwa::RegistryError>(())
//! ```

mod names;
mod registry;

pub use names::{
    ContentEncryption, ContentEncryptionAlgorithm, Curve, CurveName, HashAlgorithm, KeyEncryption,
    KeyEncryptionAlgorithm, KeyType, KeyTypeName, Kind, Name, Signature, SignatureAlgorithm,
};
pub use registry::{
    ContentEncryptionEntry, ContentEncryptionKind, CurveEntry, KeyEncryptionEntry,
    KeyManagementMode, Registry, RegistryError, SignatureEntry, Support,
};
