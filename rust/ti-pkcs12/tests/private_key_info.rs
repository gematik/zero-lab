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

//! The shared PrivateKeyInfo vectors of spec/pkcs12 (`testdata/private-key-info.json`),
//! which go/pkcs12 runs too: the P12-041 check alone, and a keyBag normalised and checked.

use std::path::Path;

use serde_json::Value;
use ti_pkcs12::{Error, decode};

fn vectors(list: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/pkcs12/testdata/private-key-info.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = json[list].as_array().unwrap().clone();
    assert!(!vectors.is_empty(), "no {list} vectors");
    vectors
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn field<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector[name].as_str().unwrap_or_default()
}

fn code(result: Result<(), &Error>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(Error::Malformed { .. }) => "malformed",
        Err(_) => "other",
    }
}

/// A DER TLV of `tag` around `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else if len < 0x100 {
        out.extend([0x81, u8::try_from(len).unwrap()]);
    } else {
        out.extend([0x82]);
        out.extend(u16::try_from(len).unwrap().to_be_bytes());
    }
    out.extend(content);
    out
}

/// A file without MAC whose only safe holds one keyBag with `value` (CONFORMANCE.md), as
/// go/pkcs12's conformance.KeyBagFile builds it.
fn key_bag_file(value: &[u8]) -> Vec<u8> {
    let data = |octets: &[u8]| {
        let mut content = unhex("06092a864886f70d010701");
        content.extend(tlv(0xa0, &tlv(0x04, octets)));
        tlv(0x30, &content)
    };
    let mut bag = unhex("060b2a864886f70d010c0a0101");
    bag.extend(tlv(0xa0, value));
    let safe = tlv(0x30, &tlv(0x30, &bag));
    let mut pfx = vec![0x02, 0x01, 0x03];
    pfx.extend(data(&tlv(0x30, &data(&safe))));
    tlv(0x30, &pfx)
}

/// P12-041: the OID, parameter, publicKey and nesting rules of the check.
#[test]
fn p12_041_the_check_agrees_with_the_shared_vectors() {
    let mut failures = Vec::new();
    for vector in vectors("check") {
        let result = ti_pkcs12::fuzz::check_private_key_info(&unhex(field(&vector, "der")));
        if code(result.as_ref().copied()) != field(&vector, "expect") {
            failures.push(format!("{}: {result:?}", field(&vector, "id")));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// P12-002, P12-004, P12-041: a keyBag's PrivateKeyInfo is normalised (a segmented
/// publicKey joined, BIT STRING segments and high tag numbers checked, depth counted from
/// the safe) and then checked.
#[test]
fn p12_002_key_bags_agree_with_the_shared_vectors() {
    let mut failures = Vec::new();
    for vector in vectors("key_bag") {
        let id = field(&vector, "id");
        match decode(&key_bag_file(&unhex(field(&vector, "value"))), "x") {
            Ok(p12) if field(&vector, "expect") == "ok" => {
                if *p12.keys[0].pkcs8 != unhex(field(&vector, "key")) {
                    failures.push(format!("{id}: another key"));
                }
            }
            Err(Error::Malformed { .. }) if field(&vector, "expect") == "malformed" => {}
            other => failures.push(format!("{id}: {:?}", other.map(|_| ()))),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
