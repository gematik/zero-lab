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

//! Any input to `Jwe::parse` and, when it parses, to `decrypt` with a key of each kind:
//! errors, never panics.
#![no_main]

use std::sync::{Arc, LazyLock};

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Curve, Registry};
use jwz::jwe::{DecryptionKey, Jwe};
use jwz::keys::{SoftwareAgreementKey, SymmetricKey};
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static BACKEND: LazyLock<Arc<RustCrypto>> = LazyLock::new(|| Arc::new(RustCrypto::new()));
static AGREEMENT: LazyLock<SoftwareAgreementKey<RustCrypto>> = LazyLock::new(|| {
    SoftwareAgreementKey::generate(Curve::P256, Arc::clone(&BACKEND)).expect("key")
});
static SYMMETRIC: LazyLock<SymmetricKey> = LazyLock::new(|| SymmetricKey::new(vec![7; 16]));

fuzz_target!(|token: &str| {
    for key in [
        DecryptionKey::Agreement(&*AGREEMENT),
        DecryptionKey::Symmetric(&SYMMETRIC),
    ] {
        if let Ok(jwe) = Jwe::parse(token, &POLICY, &REGISTRY) {
            let _ = jwe.header().epk();
            let _ = jwe.decrypt(key, BACKEND.as_ref());
        }
    }
});
