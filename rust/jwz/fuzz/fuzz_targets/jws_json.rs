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

//! Any input to the JWS JSON parser and `verify`: errors, never panics.
#![no_main]

use std::sync::{Arc, LazyLock};

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Registry, SignatureAlgorithm};
use jwz::jws;
use jwz::keys::SoftwareKey;
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static KEY: LazyLock<SoftwareKey<RustCrypto>> = LazyLock::new(|| {
    SoftwareKey::generate(
        SignatureAlgorithm::EDDSA,
        &REGISTRY,
        Arc::new(RustCrypto::new()),
    )
    .expect("key")
});

fuzz_target!(|text: &str| {
    if let Ok(all) = jws::json::parse(text, &POLICY, &REGISTRY) {
        for jws in all {
            let _ = jws.verify(&*KEY);
        }
    }
});
