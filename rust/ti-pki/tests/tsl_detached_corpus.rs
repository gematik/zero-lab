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

//! Every entry of `spec/tsl-detached/testdata/manifest.json`, the corpus an implementation
//! is held to (CONFORMANCE.md).
#![cfg(all(feature = "brainpool", feature = "dangerous-nonprod"))]

use serde_json::Value;
use ti_pki::tsl::Tsl;
use ti_pki::tsl_signature::DetachedTsl;
use ti_pki::{Env, Timestamp, TrustConfig};

const TESTDATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/tsl-detached/testdata/"
);

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{TESTDATA}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The rules each entry names: TSLDET-001, TSLDET-002, TSLDET-003, TSLDET-004, TSLDET-005,
/// TSLDET-006, TSLDET-020, TSLDET-021, TSLDET-022, TSLDET-030, TSLSIG-031 and TSLSIG-042.
#[test]
fn every_manifest_entry_meets_its_expectation() {
    let manifest: Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    let entries = manifest.as_array().unwrap();
    assert!(entries.len() >= 15, "{}", entries.len());
    for entry in entries {
        let field = |name: &str| entry[name].as_str().unwrap();
        let what = format!("{} {}", field("path"), field("signature"));
        let config = TrustConfig::preset(match field("env") {
            "prod" => Env::Prod,
            _ => Env::Ref,
        });
        let now = Timestamp::parse_rfc3339(field("time")).unwrap();
        let (xml, signature) = (read(field("path")), read(field("signature")));
        let status = entry["signer_status"].as_str().map(read);
        let result = Tsl::parse_verified_with_status(
            &xml,
            DetachedTsl {
                signature: &signature,
                signer_status: status.as_deref(),
            },
            &config,
            now,
        );
        let expect = &entry["expect"];
        if expect["result"] == "valid" {
            let verified = result.unwrap_or_else(|e| panic!("{what}: {e}"));
            let warnings: Vec<&str> = verified.warnings.iter().map(|w| w.code.as_str()).collect();
            let expected: Vec<&str> = expect["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w.as_str().unwrap())
                .collect();
            assert_eq!(warnings, expected, "{what}");
            assert_eq!(
                verified.tsl.sequence_number,
                expect["sequence_number"].as_u64().unwrap(),
                "{what}"
            );
            assert_eq!(verified.signer.serial(), &[6], "{what}");
        } else {
            let e = result
                .err()
                .unwrap_or_else(|| panic!("{what}: expected a failure"));
            assert_eq!(e.code.as_str(), expect["code"].as_str().unwrap(), "{what}");
            assert_eq!(e.rule, expect["rule"].as_str().unwrap(), "{what}");
        }
    }
}
