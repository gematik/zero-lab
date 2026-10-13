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

//! Design-time generator of the brainpool interop fixtures (`just jwz-interop` runs it
//! with the oracles):
//!
//!     cargo run -p jwz-brainpool --example interop -- keys      # once
//!     cargo run -p jwz-brainpool --example interop -- tokens    # jwz.json
//!     cargo run -p jwz-brainpool --example interop -- coverage  # COVERAGE.md

#[path = "../tests/support/interop.rs"]
mod interop;

use std::sync::Arc;

use jwz::keys::SoftwareKey;
use serde_json::{Map, Value};

use interop::{coverage, data_dir, deterministic_backend, jwz_cases, jwz_file, pretty, read_keys};

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    let result = match command.as_str() {
        "keys" => keys(),
        "tokens" => read_keys(&data_dir().join("keys.json"))
            .and_then(|keys| jwz_cases(&keys))
            .and_then(|cases| write("jwz.json", &pretty(&jwz_file(&cases)))),
        "coverage" => coverage(&data_dir()).and_then(|text| write("COVERAGE.md", &text)),
        _ => Err("usage: interop keys|tokens|coverage".into()),
    };
    if let Err(e) = result {
        eprintln!("interop {command}: {e}");
        std::process::exit(1);
    }
}

fn write(name: &str, text: &str) -> Result<(), String> {
    let path = data_dir().join(name);
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Three brainpoolP256r1 keys; regenerating them invalidates every oracle's fixtures.
fn keys() -> Result<(), String> {
    let path = data_dir().join("keys.json");
    if path.exists() {
        return Err(format!(
            "{} exists; delete it to make new keys",
            path.display()
        ));
    }
    let registry = jwz_brainpool::registry();
    let backend = deterministic_backend();
    let mut keys = Map::new();
    for name in ["bp256r1", interop::ES256_BRAINPOOL, "ecdh-bp256"] {
        let mut jwk =
            SoftwareKey::generate(jwz_brainpool::BP256R1, &registry, Arc::clone(&backend))
                .map_err(|e| e.to_string())?
                .to_jwk();
        // No `alg`: each implementation states the algorithm when it uses a key.
        jwk.alg = None;
        jwk.kid = Some(name.into());
        let value: Value = serde_json::from_str(&jwk.to_json()).map_err(|e| e.to_string())?;
        keys.insert(name.into(), value);
    }
    write("keys.json", &pretty(&Value::Object(keys)))
}
