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

// The TSL state file is whatever a crashed or hostile process left on disk: parsing answers
// an error, never a panic, and a state it accepts survives being kept for the next run, or
// the rollback check would compare against something else.
fuzz_target!(|bytes: &[u8]| {
    let Ok(state) = ti_cli::fuzz::parse_tsl_state(bytes) else {
        return;
    };
    let kept = ti_cli::fuzz::tsl_state_bytes(&state).expect("a parsed state serializes");
    assert_eq!(ti_cli::fuzz::parse_tsl_state(&kept).unwrap(), state);
});
