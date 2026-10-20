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

//! Any bytes as a key file (spec/store STORE-094): errors, never panics; a key has one
//! accepted encoding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_store::store::parse_kek_file;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(kek) = parse_kek_file(bytes, Some(0o600)) {
        let encoded = std_base64(kek.as_slice());
        let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        assert_eq!(encoded.as_bytes(), text);
    }
});

fn std_base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            out.push(if k <= c.len() { char::from(A[((n >> (18 - 6 * k)) & 63) as usize]) } else { '=' });
        }
    }
    out
}
