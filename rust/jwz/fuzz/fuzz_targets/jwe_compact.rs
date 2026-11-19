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
use jwz::jwa::{Curve, KeyEncryptionAlgorithm, Registry};
use jwz::jwe::{DecryptionKey, Encrypted, Jwe};
use jwz::keys::{KeyAgreement, SoftwareAgreementKey, SymmetricKey};
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static BACKEND: LazyLock<Arc<RustCrypto>> = LazyLock::new(|| Arc::new(RustCrypto::new()));
// A key serves one algorithm, so there is one per algorithm: every decryption path stays
// reachable, whatever `alg` the input names.
static AGREEMENT: LazyLock<Vec<SoftwareAgreementKey<RustCrypto>>> = LazyLock::new(|| {
    [
        KeyEncryptionAlgorithm::ECDH_ES,
        KeyEncryptionAlgorithm::ECDH_ES_A128KW,
        KeyEncryptionAlgorithm::ECDH_ES_A192KW,
        KeyEncryptionAlgorithm::ECDH_ES_A256KW,
    ]
    .into_iter()
    .map(|alg| {
        SoftwareAgreementKey::generate(Curve::P256, alg, &REGISTRY, Arc::clone(&BACKEND))
            .expect("key")
    })
    .collect()
});
static SYMMETRIC: LazyLock<Vec<SymmetricKey>> = LazyLock::new(|| {
    [
        (KeyEncryptionAlgorithm::DIR, 16),
        (KeyEncryptionAlgorithm::A128KW, 16),
        (KeyEncryptionAlgorithm::A192KW, 24),
        (KeyEncryptionAlgorithm::A256KW, 32),
    ]
    .into_iter()
    .map(|(alg, len)| SymmetricKey::new(vec![7; len], alg))
    .collect()
});

fn decrypt(jwe: Jwe<Encrypted>) {
    let alg = jwe.algorithm();
    if let Some(key) = AGREEMENT
        .iter()
        .find(|k| KeyAgreement::algorithm(*k) == alg)
    {
        let _ = jwe.decrypt(DecryptionKey::Agreement(key), BACKEND.as_ref());
    } else if let Some(key) = SYMMETRIC.iter().find(|k| k.algorithm() == alg) {
        let _ = jwe.decrypt(DecryptionKey::Symmetric(key), BACKEND.as_ref());
    }
}

fuzz_target!(|token: &str| {
    if let Ok(jwe) = Jwe::parse(token, &POLICY, &REGISTRY) {
        let _ = jwe.header().epk();
        decrypt(jwe);
    }
});
