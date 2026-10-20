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

//! ti-store against the corpus of spec/store (`spec/store/testdata/manifest.json`), one
//! test per rule group, named after the most specific rule.

#![cfg(feature = "test-util")]

#[path = "conformance/eval.rs"]
mod eval;

use serde_json::Value;
use ti_store::store::MemoryBackend;

/// The SQLite and files backends belong to the tools (TASK-103.4). The memory backend has
/// the semantics of section B with atomic take and batch, so it runs the scenarios written
/// for the SQLite backend.
struct Memory;

impl eval::Backends for Memory {
    type B = MemoryBackend;
    fn fresh(&self, name: &str) -> Option<MemoryBackend> {
        (name == "sqlite").then(MemoryBackend::new)
    }
}

fn manifest() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/store/testdata/manifest.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("manifest is JSON")
}

/// Runs every case of `kinds` and fails with the list of cases that disagree. A kind with
/// no case fails too, so that a renamed kind cannot pass silently.
fn check(kinds: &[&str], only_backend: Option<&str>) {
    let m = manifest();
    let mut ran = 0;
    let mut failures = Vec::new();
    for c in m["cases"].as_array().expect("cases") {
        let kind = c["kind"].as_str().expect("kind");
        if !kinds.contains(&kind) {
            continue;
        }
        if let Some(b) = only_backend
            && c["input"]["backend"].as_str() != Some(b)
        {
            continue;
        }
        ran += 1;
        let id = c["id"].as_str().expect("id");
        let (code, output) = eval::evaluate(kind, &c["input"], &Memory)
            .unwrap_or_else(|e| panic!("{id}: broken case: {}", e.0));
        let want_code = c["expect"]["code"].as_str().expect("code");
        if code != want_code {
            failures.push(format!("{id}: {code}, want {want_code}"));
        } else if code == "ok" {
            let want = c["expect"]
                .get("output")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            if output != want {
                failures.push(format!("{id}: output\n  got  {output}\n  want {want}"));
            }
        }
    }
    assert!(ran > 0, "no cases of kinds {kinds:?}");
    assert!(
        failures.is_empty(),
        "{} of {ran} cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// STORE-041: `k_value`, `k_name` and `k_index` from a data key.
#[test]
fn store_041_derivation_matches_the_corpus() {
    check(&["derive"], None);
}

/// STORE-031, STORE-032; also STORE-020, STORE-030.
#[test]
fn store_031_record_names_match_the_corpus() {
    check(&["name"], None);
}

/// STORE-034; also STORE-033.
#[test]
fn store_034_tags_match_the_corpus() {
    check(&["tag"], None);
}

/// STORE-052: sealed records byte for byte from fixed inputs; also STORE-041 to STORE-053.
#[test]
fn store_052_sealed_records_are_written_byte_for_byte() {
    check(&["seal"], None);
}

/// STORE-055: opening sealed records, and every way that must fail; also STORE-003,
/// STORE-005, STORE-050, STORE-051, STORE-056.
#[test]
fn store_055_sealed_records_open_or_fail_with_the_specified_code() {
    check(&["open"], None);
}

/// STORE-044, STORE-124: a sealed record's header names its kid, expiry and payload size
/// without a key; a plain record's has no kid.
#[test]
fn store_044_record_headers_name_kid_and_size_without_a_key() {
    use ti_store::store::{Kid, record_header};
    let m = manifest();
    let mut sealed = 0;
    for c in m["cases"].as_array().expect("cases") {
        let (kind, input, expect) = (&c["kind"], &c["input"], &c["expect"]);
        if expect["code"] != "ok" || !(kind == "seal" || kind == "plain") {
            continue;
        }
        let record =
            eval::unhex(expect["output"]["record"].as_str().expect("record")).expect("hex");
        let payload = eval::unhex(input["payload"].as_str().expect("payload")).expect("hex");
        let header = record_header(&record).expect("header");
        assert_eq!(header.payload_len, payload.len(), "{}", c["id"]);
        assert_eq!(
            header.not_after.map_or(0, |t| t.0),
            input["not_after"].as_u64().unwrap_or(0),
            "{}",
            c["id"]
        );
        if kind == "seal" {
            sealed += 1;
            let want_kid = Kid::new(input["kid"].as_str().expect("kid")).expect("kid");
            assert_eq!(header.kid, Some(want_kid), "{}", c["id"]);
        } else {
            assert_eq!(header.kid, None, "{}", c["id"]);
        }
    }
    assert!(sealed > 0, "no sealed records in the corpus");
}

/// STORE-057; also STORE-050.
#[test]
fn store_057_plain_records_match_the_corpus() {
    check(&["plain", "plain_open"], None);
}

/// STORE-063: keyring files byte for byte, and STORE-064: reading them; also STORE-060,
/// STORE-062.
#[test]
fn store_064_keyring_files_are_written_and_read_as_specified() {
    check(&["keyring_write", "keyring"], None);
}

/// STORE-094.
#[test]
fn store_094_key_files_parse_strictly() {
    check(&["kek_file"], None);
}

/// STORE-080.
#[test]
fn store_080_record_files_match_the_corpus() {
    check(&["record_file_write", "record_file"], None);
}

/// STORE-100; also STORE-086, STORE-101.
#[test]
fn store_100_format_levels_open_as_specified() {
    check(&["files_meta", "db_level"], None);
}

/// STORE-091 to STORE-094 on Linux, macOS and Windows.
#[test]
fn store_091_profiles_resolve_as_specified() {
    check(&["profile"], None);
}

/// STORE-010 to STORE-017 on the memory backend, including 100,000 records.
#[test]
fn store_015_memory_backend_passes_the_operation_scenarios() {
    check(&["scenario"], Some("sqlite"));
}
