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

//! `spec/pki-path/testdata/roots.json`: what this crate says of the A_28419 walk, the corpus
//! `go/tipki` is held to, on the real roots.json files too. Set `TI_PKI_BLESS=1` to write it again
//! after a deliberate change to a rule.
#![cfg(all(feature = "brainpool", feature = "rsa", feature = "dangerous-nonprod"))]

use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use ti_pki::roots::{self, ROOTS_NONPROD, ROOTS_PROD, verify_cross_signed, walk};
use ti_pki::{Certificate, Timestamp, algorithms};

/// `TestPki::NOW`.
const NOW: u64 = 1_767_225_600;
/// When the real files were captured, within every cross certificate's validity.
const REAL_NOW: u64 = 1_793_577_600;
const TEN_YEARS: u64 = 10 * 366 * 86_400;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-path/testdata")
}

fn fixture(name: &str) -> Certificate {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pki")
        .join(name);
    let pem = std::fs::read(path).unwrap();
    ti_pki::parse_pem_certificates(&pem).unwrap().remove(0)
}

fn anchor_file(name: &str) -> Certificate {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/anchors")
        .join(name);
    Certificate::from_der(&std::fs::read(path).unwrap()).unwrap()
}

fn b64(cert: &Certificate) -> String {
    Base64::encode_string(cert.der())
}

fn step(stop: Option<&String>) -> Value {
    let Some(stop) = stop else { return Value::Null };
    match stop.split("A_28419 step ").nth(1) {
        Some(rest) => json!(rest.chars().next().unwrap().to_string()),
        None if stop.contains("does not parse") => json!("parse"),
        None if stop.contains("not in roots.json") => json!("absent"),
        None if stop.contains("loops back") => json!("loop"),
        None => json!("other"),
    }
}

fn walk_case(name: &str, roots_json: &str, anchor: &Certificate, now: u64) -> Value {
    let entries = roots::parse(roots_json.as_bytes());
    let outcome = entries.map_or_else(
        |_| json!({ "parse_error": true }),
        |entries| match walk(anchor, &entries, Timestamp(now), algorithms::DEFAULT) {
            Err(_) => json!({ "anchor_absent": true }),
            Ok(walked) => json!({
                "trusted": walked.trusted.iter().map(Certificate::subject_cn).collect::<Vec<_>>(),
                "forward_stop": step(walked.forward_stop.as_ref()),
                "backward_stop": step(walked.backward_stop.as_ref()),
            }),
        },
    );
    json!({ "name": name, "anchor": b64(anchor), "now": now, "outcome": outcome })
}

/// Documents the parser reads or refuses, whatever the walk would make of them.
fn documents(root: &Certificate) -> Vec<(&'static str, String)> {
    let cert = b64(root);
    vec![
        ("empty", "[]".to_owned()),
        ("empty wrapped", r#"{"roots":[]}"#.to_owned()),
        ("no list", r#"{"other":[]}"#.to_owned()),
        ("null list", r#"{"roots":null}"#.to_owned()),
        ("not json", "nope".to_owned()),
        ("an entry not an object", "[1]".to_owned()),
        ("no cert", r#"[{"cn":"x"}]"#.to_owned()),
        ("null cert", r#"[{"cert":null}]"#.to_owned()),
        ("cert not base64", r#"[{"cert":"***"}]"#.to_owned()),
        ("cert not a certificate", r#"[{"cert":"AAAA"}]"#.to_owned()),
        ("null cn", format!(r#"[{{"cert":"{cert}","cn":null}}]"#)),
        (
            "next not base64",
            format!(r#"[{{"cert":"{cert}","next":"***"}}]"#),
        ),
        (
            "next a number",
            format!(r#"[{{"cert":"{cert}","next":1}}]"#),
        ),
        (
            "another spelling of cert",
            format!(r#"[{{"CERT":"{cert}"}}]"#),
        ),
        (
            "unknown fields are ignored",
            format!(r#"[{{"cert":"{cert}","extra":{{}}}}]"#),
        ),
    ]
}

fn synthetic() -> Vec<Value> {
    let (rca1, rca7) = (fixture("rca1.pem"), fixture("rca7.pem"));
    let (forward, backward) = (
        fixture("cross-rca1-for-rca7.pem"),
        fixture("cross-rca7-for-rca1.pem"),
    );
    let entry = |cert: &Certificate, prev: Value, next: Value| json!({ "cert": b64(cert), "cn": cert.subject_cn(), "prev": prev, "next": next });
    let good = json!([
        entry(&rca1, Value::Null, json!(b64(&forward))),
        entry(&rca7, json!(b64(&backward)), Value::Null),
    ]);
    let with = |list: Value| list.to_string();
    let mut cases: Vec<(&str, String, &Certificate, u64)> = vec![
        ("from the older root", with(good.clone()), &rca1, NOW),
        ("from the newer root", with(good.clone()), &rca7, NOW),
        (
            "wrapped",
            json!({ "roots": good, "version": 1 }).to_string(),
            &rca1,
            NOW,
        ),
        (
            "before the cross certificate",
            with(good.clone()),
            &rca1,
            NOW - TEN_YEARS,
        ),
        (
            "after the cross certificate",
            with(good.clone()),
            &rca1,
            NOW + TEN_YEARS,
        ),
        (
            "anchor absent",
            with(json!([entry(&rca7, Value::Null, Value::Null)])),
            &rca1,
            NOW,
        ),
        (
            "cross does not parse",
            with(json!([entry(&rca1, Value::Null, json!("AAAA"))])),
            &rca1,
            NOW,
        ),
        (
            "names a root that is absent",
            with(json!([entry(&rca1, Value::Null, json!(b64(&forward)))])),
            &rca1,
            NOW,
        ),
        (
            "loops",
            with(json!([
                entry(&rca1, Value::Null, json!(b64(&backward))),
                entry(&rca7, Value::Null, Value::Null)
            ])),
            &rca1,
            NOW,
        ),
        (
            "empty strings are no links",
            with(json!([entry(&rca1, json!(""), json!(""))])),
            &rca1,
            NOW,
        ),
    ];
    let documents = documents(&rca1);
    cases.extend(
        documents
            .into_iter()
            .map(|(name, text)| (name, text, &rca1, NOW)),
    );
    cases
        .iter()
        .map(|(name, text, anchor, now)| {
            let mut case = walk_case(name, text, anchor, *now);
            case["json"] = json!(text);
            case
        })
        .collect()
}

fn real() -> Vec<Value> {
    let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
    let mut cases = Vec::new();
    for (name, json_text, file, anchor) in [
        (
            "prod",
            text(ROOTS_PROD),
            "roots-prod.json",
            anchor_file("GEM.RCA7.der"),
        ),
        (
            "prod from RCA8",
            text(ROOTS_PROD),
            "roots-prod.json",
            anchor_file("GEM.RCA8.der"),
        ),
        (
            "nonprod",
            text(ROOTS_NONPROD),
            "roots-nonprod.json",
            anchor_file("GEM.RCA7-TEST-ONLY.der"),
        ),
    ] {
        for now in [REAL_NOW, REAL_NOW + TEN_YEARS] {
            let mut case = walk_case(name, &json_text, &anchor, now);
            case["file"] = json!(file);
            cases.push(case);
        }
    }
    cases
}

/// Every cross certificate against every root, as the seven steps see them.
fn steps() -> Vec<Value> {
    let crosses = [
        "cross-rca1-for-rca7.pem",
        "cross-rca7-for-rca1.pem",
        "cross-rca1-not-rca.pem",
        "sub-ca-hba.pem",
    ];
    let roots_ = ["rca1.pem", "rca7.pem", "rogue-root.pem"];
    let mut cases = Vec::new();
    for cross in crosses {
        for anchor in roots_ {
            for subordinate in roots_ {
                for now in [NOW, NOW - TEN_YEARS, NOW + TEN_YEARS] {
                    let step = verify_cross_signed(
                        &fixture(anchor),
                        &fixture(cross),
                        &fixture(subordinate),
                        Timestamp(now),
                        algorithms::DEFAULT,
                    )
                    .err()
                    .map(|e| e.step);
                    cases.push(json!({
                        "cross": cross, "anchor": anchor, "subordinate": subordinate, "now": now, "step": step,
                    }));
                }
            }
        }
    }
    cases
}

/// ROOTS-001 to ROOTS-003: the corpus is what this crate says, and the real files reach all ten roots.
#[test]
fn roots_001_the_corpus_is_what_ti_pki_says() {
    let real = real();
    assert_eq!(
        real[0]["outcome"]["trusted"].as_array().unwrap().len(),
        10,
        "{}",
        real[0]
    );
    assert_eq!(
        real[4]["outcome"]["trusted"].as_array().unwrap().len(),
        10,
        "{}",
        real[4]
    );
    let corpus = json!({ "synthetic": synthetic(), "real": real, "steps": steps() });
    let written = serde_json::to_string_pretty(&corpus).unwrap() + "\n";
    let path = testdata().join("roots.json");
    if std::env::var_os("TI_PKI_BLESS").is_some() {
        std::fs::write(&path, written).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(&path).expect("TI_PKI_BLESS=1 writes the corpus");
    assert_eq!(
        stored, written,
        "the corpus differs: TI_PKI_BLESS=1 after a deliberate change"
    );
}
