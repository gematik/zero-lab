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

#![no_main]

use libfuzzer_sys::fuzz_target;

// A cache file is whatever a crashed or hostile process left on disk: decoding answers a
// miss, never a panic, and an entry it accepts survives being written back, or a cache hit
// could change what the next run reads.
fuzz_target!(|bytes: &[u8]| {
    let Some(entry) = ti_cli::fuzz::decode(bytes) else {
        return;
    };
    let encoded = ti_cli::fuzz::encode(&entry).expect("a decoded entry encodes");
    let again = ti_cli::fuzz::decode(&encoded).expect("an encoded entry decodes");
    assert_eq!(again, entry);
    assert_eq!(ti_cli::fuzz::encode(&again).unwrap(), encoded);
});
