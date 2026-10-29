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

//! Any bytes as a PKCS#12 file with any password: `decode` never panics, ends with one
//! of the result codes of spec/pkcs12, and what it returns is consistent with the rules
//! that code stands for. The input is a length byte, the password and the file, so
//! that the seeds from spec/pkcs12 keep their passwords and get past the MAC.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_pkcs12::{Error, MAX_ITERATIONS, decode, is_pkcs12};

fuzz_target!(|input: &[u8]| {
    let Some((&length, rest)) = input.split_first() else {
        return;
    };
    let (password, file) = rest.split_at(usize::from(length).min(rest.len()));
    let password = String::from_utf8_lossy(password);
    match decode(file, &password) {
        Ok(p12) => {
            assert!(is_pkcs12(file));
            for pair in p12.pairs() {
                assert!(pair.certificate < p12.certificates.len() && pair.key < p12.keys.len());
            }
            if let Some(mac) = &p12.mac {
                assert!((1..=MAX_ITERATIONS).contains(&mac.iterations), "P12-036");
            }
        }
        Err(Error::LimitExceeded { iterations, .. }) => {
            assert!(iterations > MAX_ITERATIONS, "P12-036");
        }
        Err(Error::Malformed { .. }) => {}
        Err(Error::MacMismatch | Error::DecryptFailed | Error::UnsupportedAlgorithm(_)) => {
            assert!(is_pkcs12(file));
        }
        Err(e) => panic!("no result code of spec/pkcs12: {e}"),
    }
});
