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

//! A bundle as a server reads it from a mounted directory: refused or decoded, never a panic,
//! and what decodes encodes to what decodes the same.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_pki::load::Bundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = Bundle::from_slice(data) {
        assert_eq!(Bundle::from_slice(&bundle.to_vec()).as_ref().ok(), Some(&bundle));
    }
});
