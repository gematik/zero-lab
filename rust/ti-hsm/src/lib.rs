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

//! Keys in a hardware security module, reached over PKCS#11 alone.
//!
//! A workload that keeps a key in an HSM reaches it through a key provider sidecar over a
//! Unix socket; the vendor's library is never in the workload's image
//! ([servers](../../docs/design/servers.md), rule 6). This crate is that sidecar's way to
//! the key: it loads the PKCS#11 module it is given, and a software token in development
//! goes through exactly the calls a vendor's module gets in production.
//!
//! [`Module::load`] loads and initialises a module, [`Module::open`] logs in to a token by
//! its label, and a [`Token`] finds or makes keys by label and uses them: ECDSA signatures
//! over a digest or a message, AES-256-GCM encryption and decryption with associated data.
//! Every key is made on the token, not extractable, and for its one use. An error names the
//! operation, the key's label and the PKCS#11 return code, never data.

mod pkcs11;

pub use pkcs11::{
    Curve, Error, Iv, KeyEncryptionKey, KeyFacts, MessageDigest, Module, Sealed, SignInput,
    SigningKey, Token,
};
