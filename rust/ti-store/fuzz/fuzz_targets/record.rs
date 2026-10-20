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

//! Any bytes as a sealed or plain record (spec/store section F): errors, never panics, and
//! nothing opens without the right key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_store::store::{DataKey, Kid, Namespace, derive, open_plain, open_sealed, record_header};
use ti_types::Timestamp;

fuzz_target!(|input: (&[u8], u64)| {
    let (record, now) = input;
    let keys = derive(&DataKey::from_bytes([7; 32]));
    let kid = Kid::new("k1").expect("kid");
    let ns = Namespace::new("popp").expect("namespace");
    let name = keys.name(&ns, b"id").expect("name");
    let opened = open_sealed(|k| (k == &kid).then(|| keys.value_key()), &[1; 16], &ns, &name, Timestamp(now), record);
    // Opening needs a tag made with the key; random bytes never carry one.
    assert!(opened.is_err());
    // The header agrees with what opening a plain record finds; a sealed one's header is
    // only read, never trusted.
    let header = record_header(record);
    if let Ok(plain) = open_plain(Timestamp(now), record) {
        let header = header.expect("a plain record that opens has a header");
        assert_eq!(header.kid, None);
        assert_eq!(header.not_after, plain.not_after);
        assert_eq!(header.payload_len, plain.payload.len());
    }
});
