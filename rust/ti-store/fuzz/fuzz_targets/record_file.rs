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

//! Any bytes as a record file of the files backend (spec/store section I): errors, never
//! panics; what parses encodes to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_store::store::files::{FilesMeta, encode_record, parse_record};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(record) = parse_record(bytes) {
        assert_eq!(encode_record(&record), bytes);
    }
    if let Ok(meta) = FilesMeta::parse(bytes) {
        assert_eq!(meta.encode(), bytes);
    }
});
