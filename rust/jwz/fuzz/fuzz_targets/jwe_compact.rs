/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
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
