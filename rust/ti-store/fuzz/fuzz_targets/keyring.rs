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

//! Any bytes as a keyring file (spec/store section G): errors, never panics; what parses
//! encodes to the same bytes, and unwrapping under a wrong key never succeeds.
#![no_main]

use futures_lite::future::block_on;
use libfuzzer_sys::fuzz_target;
use ti_store::store::{KeyFileWrapper, Keyring, KeyringFile, OsRandom};
use zeroize::Zeroizing;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(file) = KeyringFile::parse(bytes) {
        assert_eq!(file.encode(), bytes, "STORE-005: one encoding per keyring");
        let wrapper = KeyFileWrapper::new(Zeroizing::new([9; 32]), OsRandom);
        assert!(block_on(Keyring::open(&file, &wrapper, OsRandom)).is_err());
    }
});
