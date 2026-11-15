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


//! Any bytes as one BER element: the normalisation of P12-002 never panics; what it returns
//! is DER in every layer, as the `der` crate reads it, and normalising it again changes
//! nothing; input that is DER already comes back unchanged.
#![no_main]

use der::asn1::AnyRef;
use der::{Decode, Reader, SliceReader, Tag, Tagged};
use libfuzzer_sys::fuzz_target;
use ti_pkcs12::fuzz::ber_to_der;

/// Universal string types, which DER writes primitive only (X.690 §10.2).
fn is_string(tag: Tag) -> bool {
    tag.is_universal() && matches!(tag.number().0, 3 | 4 | 12 | 18..=22 | 25..=28 | 30)
}

/// Whether `element` is DER in every layer: `der` reads each element in DER mode
/// (definite, minimal lengths), and the content of every constructed one again.
fn is_der(element: AnyRef<'_>, depth: usize) -> bool {
    if !element.tag().is_constructed() {
        return true;
    }
    if is_string(element.tag()) || depth > 64 {
        return false;
    }
    let Ok(mut reader) = SliceReader::new(element.value()) else {
        return false;
    };
    while !reader.is_finished() {
        match AnyRef::decode(&mut reader) {
            Ok(child) if is_der(child, depth + 1) => {}
            _ => return false,
        }
    }
    true
}

fn is_der_bytes(bytes: &[u8]) -> bool {
    AnyRef::from_der(bytes).is_ok_and(|element| is_der(element, 0))
}

fuzz_target!(|bytes: &[u8]| {
    if is_der_bytes(bytes) {
        assert_eq!(ber_to_der(bytes).expect("DER is BER"), bytes, "DER changed");
    }
    let Ok(der) = ber_to_der(bytes) else {
        return;
    };
    assert!(is_der_bytes(&der), "output is not DER");
    assert_eq!(ber_to_der(&der).expect("the output normalises"), der, "not idempotent");
});
