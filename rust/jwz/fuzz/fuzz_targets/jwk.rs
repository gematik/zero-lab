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

//! Any input to JWK and JWK Set parsing, `check`, `public`, serialization and the
//! thumbprint: errors, never panics; a parsed key survives its own serialization.
#![no_main]

use std::sync::LazyLock;

use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{HashAlgorithm, Registry};
use jwz::jwk::{Jwk, JwkSet};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static BACKEND: LazyLock<RustCrypto> = LazyLock::new(RustCrypto::new);

fuzz_target!(|text: &str| {
    if let Ok(jwk) = Jwk::parse(text) {
        let _ = jwk.check(&REGISTRY);
        let _ = jwk.public();
        let again = Jwk::parse(&jwk.to_json()).expect("a parsed key reparses");
        assert_eq!(again, jwk);
        if let Some(sha256) = BACKEND.hash(HashAlgorithm::Sha256) {
            let _ = jwk.thumbprint(sha256);
        }
    }
    let _ = JwkSet::parse(text);
});
