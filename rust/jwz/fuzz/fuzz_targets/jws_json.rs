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
