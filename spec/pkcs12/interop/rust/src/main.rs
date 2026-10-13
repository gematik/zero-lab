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

//! rust/ti-pkcs12 adapter of the PKCS#12 conformance harness:
//!
//! ```text
//! p12-decoder-rust decode --password-file FILE P12
//! ```
//!
//! Writes the JSON of spec/pkcs12/CONFORMANCE.md (command-line contract).

use std::fmt::Write as _;
use std::process::exit;

use sha2::{Digest, Sha256};
use ti_pkcs12::Error;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "decode" || args[1] != "--password-file" {
        eprintln!("usage: p12-decoder-rust decode --password-file FILE P12");
        exit(2);
    }
    let read = |path: &str| {
        std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("{path}: {e}");
            exit(2)
        })
    };
    let password = read(&args[2]);
    let data = read(&args[3]);
    let Ok(password) = String::from_utf8(password) else {
        // ti_pkcs12::decode takes &str; the corpus passwords are UTF-8.
        println!("{}", failure("malformed", "password is not UTF-8"));
        return;
    };
    println!("{}", decode(&data, &password));
}

fn decode(data: &[u8], password: &str) -> String {
    let p12 = match ti_pkcs12::decode(data, password) {
        Ok(p12) => p12,
        Err(e) => {
            let code = match e {
                Error::Malformed { .. } => "malformed",
                Error::MacMismatch => "mac_mismatch",
                Error::DecryptFailed => "decryption_failed",
                Error::UnsupportedAlgorithm(_) => "unsupported_algorithm",
                _ => "error",
            };
            return failure(code, &e.to_string());
        }
    };
    let item = |der: &[u8], name: &Option<String>, id: &Option<Vec<u8>>| {
        let mut s = format!("{{\"sha256\":\"{}\"", hex(&Sha256::digest(der)));
        if let Some(name) = name {
            write!(s, ",\"friendly_name\":{}", json(name)).unwrap();
        }
        if let Some(id) = id {
            write!(s, ",\"local_key_id\":\"{}\"", hex(id)).unwrap();
        }
        s + "}"
    };
    let certificates: Vec<String> = p12
        .certificates
        .iter()
        .map(|c| item(&c.der, &c.friendly_name, &c.local_key_id))
        .collect();
    let keys: Vec<String> = p12
        .keys
        .iter()
        .map(|k| item(&k.pkcs8, &k.friendly_name, &k.local_key_id))
        .collect();
    let pairs: Vec<String> = p12
        .pairs()
        .iter()
        .map(|p| format!("[{},{}]", p.certificate, p.key))
        .collect();
    let mac = p12.mac.as_ref().map_or("null".to_owned(), |m| {
        json(&m.digest.to_ascii_lowercase().replace('-', ""))
    });
    format!(
        "{{\"code\":\"ok\",\"certificates\":[{}],\"keys\":[{}],\"pairs\":[{}],\"mac\":{mac}}}",
        certificates.join(","),
        keys.join(","),
        pairs.join(",")
    )
}

fn failure(code: &str, detail: &str) -> String {
    format!(
        "{{\"code\":\"{code}\",\"detail\":{},\"certificates\":[],\"keys\":[],\"pairs\":[],\"mac\":null}}",
        json(detail)
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

fn json(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out + "\""
}
