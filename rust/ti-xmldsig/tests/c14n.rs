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

//! TSLSIG-016 against the specifications' examples and the W3C interoperability vectors in
//! `spec/tsl-xmldsig/testdata/c14n`.

use std::path::{Path, PathBuf};

use ti_xmldsig::{Document, Limits};

fn testdata(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/tsl-xmldsig/testdata/c14n")
        .join(path)
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(testdata(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn assert_c14n(expected: &str, actual: &[u8]) {
    assert_eq!(
        String::from_utf8_lossy(actual),
        String::from_utf8_lossy(&read(expected)),
        "{expected}"
    );
}

#[test]
fn tslsig_016_specification_examples_whole_document() {
    let mut checked = 0;
    for entry in std::fs::read_dir(testdata("spec")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "xml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        let input = std::fs::read(&path).unwrap();
        let doc = Document::parse(&input, &Limits::TSL).unwrap();
        assert_c14n(&format!("spec/{name}.c14n"), &doc.exc_c14n().unwrap());
        checked += 1;
    }
    assert_eq!(checked, 7);
}

#[test]
fn tslsig_016_exclusive_canonicalization_section_2_2() {
    for name in ["exc-c14n-2.2-a", "exc-c14n-2.2-b"] {
        let input = read(&format!("spec/{name}.xml"));
        let doc = Document::parse(&input, &Limits::TSL).unwrap();
        let elem2 = doc.exc_c14n_by_name("http://example.net", "elem2").unwrap();
        assert_c14n(&format!("spec/{name}.elem2.c14n"), &elem2);
    }
}

#[test]
fn tslsig_016_w3c_merlin_exc_c14n_one() {
    let input = read("w3c/merlin-exc-c14n-one.xml");
    let doc = Document::parse(&input, &Limits::TSL).unwrap();
    assert_c14n(
        "w3c/merlin-exc-c14n-one.id-to-be-signed.c14n",
        &doc.exc_c14n_by_id("to-be-signed").unwrap(),
    );
    assert_c14n(
        "w3c/merlin-exc-c14n-one.SignedInfo.c14n",
        &doc.exc_c14n_by_name("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")
            .unwrap(),
    );
}
