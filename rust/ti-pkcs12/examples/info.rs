/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
 */

//! Prints what a PKCS#12 file holds.
//!
//! ```console
//! cargo run -p ti-pkcs12 --example info -- identity.p12 [PASSWORD]
//! ```
//!
//! The password defaults to `00`, gematik's test-card convention.

use std::fmt::Write as _;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: info FILE [PASSWORD]");
        std::process::exit(2);
    };
    let password = args.next().unwrap_or_else(|| "00".to_owned());
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(4);
    });
    let p12 = match ti_pkcs12::decode(&bytes, &password) {
        Ok(p12) => p12,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    match &p12.mac {
        Some(mac) => println!("mac          {} × {}", mac.digest, mac.iterations),
        None => println!("mac          none"),
    }
    for encryption in &p12.encryption {
        println!(
            "encryption   {:?}: {}",
            encryption.target, encryption.algorithm
        );
    }
    for (i, cert) in p12.certificates.iter().enumerate() {
        println!(
            "certificate  #{i} {} bytes, name {:?}, localKeyId {}",
            cert.der.len(),
            cert.friendly_name.as_deref().unwrap_or("-"),
            hex(cert.local_key_id.as_deref())
        );
    }
    for (i, key) in p12.keys.iter().enumerate() {
        let algorithm = key.algorithm().map_or_else(
            || "unknown".to_owned(),
            |(oid, curve)| curve.map_or_else(|| oid.to_string(), |c| format!("{oid} {c}")),
        );
        println!(
            "key          #{i} {algorithm}, name {:?}, localKeyId {}",
            key.friendly_name.as_deref().unwrap_or("-"),
            hex(key.local_key_id.as_deref())
        );
    }
    for pair in p12.pairs() {
        println!(
            "pair         certificate #{} with key #{}",
            pair.certificate, pair.key
        );
    }
}

fn hex(bytes: Option<&[u8]>) -> String {
    bytes.map_or_else(
        || "-".to_owned(),
        |bytes| {
            bytes.iter().fold(String::new(), |mut out, b| {
                write!(out, "{b:02x}").unwrap();
                out
            })
        },
    )
}
