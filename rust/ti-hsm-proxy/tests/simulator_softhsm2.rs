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

//! The simulator mode's keys derived from a seed, on SoftHSM2 (TASK-389 #3): the same seed
//! gives every token the same keys, another seed other keys.
//!
//! Gated like the token suite (`just hsm-proxy-softhsm2`); needs the feature `simulator`.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use cryptoki::types::AuthPin;
use ti_hsm_proxy::{Digest, HsmProxy, Iv, KeyKind, KeySpec, MissingKeys, Module};

fn proxy(module: &Module, token: &str, seed: [u8; 32]) -> HsmProxy {
    let pin = AuthPin::from("user-pin-TEST-ONLY");
    module
        .provision(token, &AuthPin::from("so-pin-TEST-ONLY"), &pin)
        .expect("the token is provisioned");
    let pool = module
        .pool(token, &pin, NonZeroUsize::new(1).unwrap())
        .unwrap();
    let keys = [
        ("sig", KeyKind::EcdsaP256),
        ("sig-384", KeyKind::EcdsaP384),
        ("kek", KeyKind::Aes256Gcm),
    ]
    .map(|(key_id, kind)| KeySpec {
        key_id: key_id.to_owned(),
        kind,
    });
    HsmProxy::start(
        pool,
        &keys,
        MissingKeys::Derive(seed),
        Duration::from_secs(5),
        Iv::Random,
        String::new(),
    )
    .expect("the keys are derived onto the token")
}

/// TASK-389 #3: two tokens started with one seed hold the same keys: the same public keys on
/// both curves, and what one encrypts the other decrypts; a token started again finds its
/// keys rather than deriving them twice; another seed gives other keys. The derived keys are
/// sensitive and not extractable, so the sidecar serves them.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-proxy-softhsm2"]
fn task_389_3_one_seed_gives_every_token_the_same_keys() {
    let path = std::env::var_os("TI_HSM_PKCS11_MODULE_PATH")
        .map(PathBuf::from)
        .expect("TI_HSM_PKCS11_MODULE_PATH: the PKCS#11 module to drive (just hsm-proxy-softhsm2)");
    let module = Module::load(&path).expect("the module loads");
    let seed = [42u8; 32];
    let a = proxy(&module, "sim-a", seed);
    let b = proxy(&module, "sim-b", seed);
    let other = proxy(&module, "sim-other", [43u8; 32]);

    for key in ["sig", "sig-384"] {
        assert_eq!(
            a.public_key(key).unwrap(),
            b.public_key(key).unwrap(),
            "{key}"
        );
        assert_ne!(
            a.public_key(key).unwrap(),
            other.public_key(key).unwrap(),
            "{key}"
        );
    }
    let sealed = a
        .encrypt("kek", b"a data-encryption key", b"row 1")
        .unwrap();
    assert_eq!(
        b.decrypt("kek", &sealed, b"row 1").unwrap(),
        b"a data-encryption key"
    );
    assert!(other.decrypt("kek", &sealed, b"row 1").is_err());
    assert_eq!(b.sign("sig", &[7; 32], Digest::None).unwrap().len(), 64);

    let again = proxy(&module, "sim-a", seed);
    assert_eq!(
        again.public_key("sig").unwrap(),
        a.public_key("sig").unwrap()
    );

    // Kept to the end of the process, as the sidecar keeps it.
    std::mem::forget(module);
}
