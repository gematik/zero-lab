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

//! The spec/store conformance adapter of ti-store: reads one request per line on standard
//! input and answers one per line (spec/store CONFORMANCE.md).
//!
//! ```sh
//! cd spec/store/tool
//! go run . verify -- cargo run -q --manifest-path ../../../rust/Cargo.toml -p ti-store --features test-util --example conformance
//! ```

#[path = "../tests/conformance/eval.rs"]
mod eval;

use std::io::{BufRead, Write};

use serde_json::{Value, json};
use ti_store::store::MemoryBackend;

/// No backend of ti-store itself does I/O; the tools' backends have their own adapters.
struct NoBackends;

impl eval::Backends for NoBackends {
    type B = MemoryBackend;
    fn fresh(&self, _name: &str) -> Option<MemoryBackend> {
        None
    }
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let req: Value = serde_json::from_str(&line?).map_err(std::io::Error::other)?;
        let id = req["id"].clone();
        let resp = match eval::evaluate(
            req["kind"].as_str().unwrap_or(""),
            &req["input"],
            &NoBackends,
        ) {
            Ok((code, output)) if code == "ok" => json!({"id": id, "code": code, "output": output}),
            Ok((code, _)) => json!({"id": id, "code": code}),
            Err(e) => {
                eprintln!("{id}: broken case: {}", e.0);
                json!({"id": id, "code": "unsupported"})
            }
        };
        writeln!(out, "{resp}")?;
        out.flush()?;
    }
    Ok(())
}
