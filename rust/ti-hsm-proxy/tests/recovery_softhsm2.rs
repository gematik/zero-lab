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

//! A token that logs the application out, as one that restarts does, against the sidecar's
//! operations (TASK-389). A logout ends the login of every session of the process, so this
//! suite is a test binary of its own, and its one test runs alone.
//!
//! Gated like the token suite (`just hsm-proxy-softhsm2`), and needs the `conformance`
//! feature for the probe that logs out.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use cryptoki::types::AuthPin;
use ti_hsm_proxy::{Digest, HsmProxy, Iv, KeyKind, KeySpec, MissingKeys, Module};

const TOKEN: &str = "ti-hsm-proxy-recovery";

/// TASK-389: after the token logs the application out, the next call of each operation
/// succeeds: its session is replaced and logged in again, its key found again by its label,
/// and the call tried once more. The health check that meets the logout reports it, and the
/// one after it is serving again.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-proxy-softhsm2"]
fn task_389_the_sidecar_recovers_from_a_token_that_logs_it_out() {
    let path = std::env::var_os("TI_HSM_PKCS11_MODULE_PATH")
        .map(PathBuf::from)
        .expect("TI_HSM_PKCS11_MODULE_PATH: the PKCS#11 module to drive (just hsm-proxy-softhsm2)");
    let pin = AuthPin::from("user-pin-TEST-ONLY");
    let module = Module::load(&path).expect("the module loads");
    module
        .provision(TOKEN, &AuthPin::from("so-pin-TEST-ONLY"), &pin)
        .expect("the token is provisioned");
    let wait = Duration::from_secs(5);
    let keys =
        [("sig", KeyKind::EcdsaP256), ("kek", KeyKind::Aes256Gcm)].map(|(key_id, kind)| KeySpec {
            key_id: key_id.to_owned(),
            kind,
        });
    let pool = module
        .pool(TOKEN, &pin, NonZeroUsize::new(2).unwrap())
        .unwrap();
    let proxy = HsmProxy::start(
        pool,
        &keys,
        MissingKeys::Make,
        wait,
        Iv::Random,
        String::new(),
    )
    .expect("the keys are on the token");
    let digest = [7u8; 32];
    proxy.sign("sig", &digest, Digest::None).unwrap();
    let sealed = proxy
        .encrypt("kek", b"a data-encryption key", b"aad")
        .unwrap();

    let log_out = || {
        module
            .open(TOKEN, &pin)
            .and_then(|token| token.log_out())
            .expect("the application is logged out");
    };

    log_out();
    assert_eq!(proxy.sign("sig", &digest, Digest::None).unwrap().len(), 64);
    log_out();
    assert_eq!(
        proxy.decrypt("kek", &sealed, b"aad").unwrap(),
        b"a data-encryption key"
    );
    log_out();
    assert!(proxy.public_key("sig").is_ok());

    log_out();
    let after: Vec<bool> = (0..3).map(|_| proxy.health().serving).collect();
    assert_eq!(after, [false, true, true]);
    // Kept to the end of the process, as the sidecar keeps it: SoftHSM2 crashes in its exit
    // handlers once it was unloaded after a logout.
    std::mem::forget(module);
}
