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

//! The HSM proxy sidecar: gematik's HSM proxy interface on keys reached over PKCS#11 alone.
//!
//! A workload that keeps a key in an HSM reaches it through a key provider sidecar over a
//! Unix socket; the vendor's library is never in the workload's image
//! ([servers](../../docs/design/servers.md), rule 6). This crate is that sidecar: it loads
//! the PKCS#11 module it is given, and a software token in development goes through
//! exactly the calls a vendor's module gets in production.
//!
//! Three layers, each usable without the next:
//!
//! - the PKCS#11 adapter ([`Module`], [`Token`], [`Pool`]);
//! - the interface's operations without a transport ([`HsmProxy`]);
//! - the transports ([`transport`]): what they share, the listener and its TLS, behind the
//!   feature `transport`, and the gRPC one ([`transport::grpc`]) behind `grpc`, on by
//!   default, the one module that depends on tonic.
//!
//! [`Module::load`] loads and initialises a module, [`Module::open`] logs in to a token by
//! its label, and a [`Token`] finds or makes keys by label and uses them: ECDSA signatures
//! over a digest or a message, AES-256-GCM encryption and decryption with associated data.
//! Every key is made on the token, not extractable, and for its one use. An error names the
//! operation, the key's label and the PKCS#11 return code, never data.
//!
//! A session runs one operation at a time; [`Module::pool`] opens a fixed number of them
//! and a [`Pool`] lends one to each caller, so that a server's callers run in parallel up
//! to what the token allows.

mod pkcs11;
mod pool;
mod service;
#[cfg(feature = "transport")]
pub mod transport;

#[cfg(feature = "conformance")]
pub use pkcs11::KeyFacts;
pub use pkcs11::{
    Curve, Error, Iv, KeyEncryptionKey, MessageDigest, Module, Sealed, SignInput, SigningKey, Token,
};
pub use pool::Pool;
pub use service::{
    Certificate, Digest, Failure, FailureKind, Health, HsmProxy, KeyKind, KeySpec, MAX_DATA_LEN,
    MissingKeys, PublicKey, StartError,
};
