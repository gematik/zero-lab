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

//! `docs/traceability.md`: every specification reference in jwz's source comments
//! (`// RFC 7516 §5.2: …`, `// NIST SP 800-56A §5.8.1 …`), where it is implemented and
//! which tests are named after it (`rfc_7516_5_2_…`). This test builds the table and
//! fails if the committed file differs; `JWZ_BLESS=1 cargo test -p jwz --test
//! traceability` rewrites it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A reference in normal form: `RFC 7516 §5.2`, `RFC 7518 Appendix C`,
/// `NIST SP 800-56A §5.8.1`, or the bare `RFC 7516`.
fn references(comment: &str) -> Vec<String> {
    let mut found = Vec::new();
    let words: Vec<&str> = comment
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')' | ':'))
        .filter(|w| !w.is_empty())
        .collect();
    let section = |w: Option<&&str>| -> Option<String> {
        let w = w?.strip_prefix('§')?;
        let s: String = w
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let s = s.trim_end_matches('.').to_string();
        (!s.is_empty()).then_some(s)
    };
    for (i, word) in words.iter().enumerate() {
        if *word == "RFC" {
            let Some(number) = words
                .get(i + 1)
                .filter(|n| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()))
            else {
                continue;
            };
            let reference = if let Some(s) = section(words.get(i + 2)) {
                format!("RFC {number} §{s}")
            } else if words.get(i + 2) == Some(&"Appendix") {
                let appendix: String = words
                    .get(i + 3)
                    .map(|a| a.trim_end_matches('.').to_string())
                    .unwrap_or_default();
                format!("RFC {number} Appendix {appendix}")
            } else {
                format!("RFC {number}")
            };
            found.push(reference);
        } else if *word == "800-56A"
            && i >= 2
            && words[i - 1] == "SP"
            && let Some(s) = section(words.get(i + 1))
        {
            found.push(format!("NIST SP 800-56A §{s}"));
        }
    }
    found
}

/// The test-name prefix a reference maps to: `rfc_7516_5_2`, `rfc_7518_appendix_c`.
fn slug(reference: &str) -> String {
    reference
        .to_lowercase()
        .replace("nist sp 800-56a", "sp_800_56a")
        .replace(['§', '.', ' '], "_")
        .replace("__", "_")
        .trim_end_matches('_')
        .to_string()
}

/// A test: its name and the references its doc comment cites.
struct Test {
    name: String,
    cites: Vec<String>,
}

fn is_whole_document(reference: &str) -> bool {
    !reference.contains('§') && !reference.contains("Appendix")
}

/// Whether `cited` is `reference` or one of its subsections (`§4.6.1.1` of `§4.6.1`).
fn within(cited: &str, reference: &str) -> bool {
    cited == reference
        || (!is_whole_document(reference)
            && cited
                .strip_prefix(reference)
                .is_some_and(|rest| rest.starts_with('.')))
}

/// The tests named after `reference` or a subsection of it. A whole document (`RFC
/// 7515` without a section) names no tests: every test of it would match.
fn named_tests<'a>(reference: &str, tests: &'a [Test]) -> impl Iterator<Item = &'a Test> {
    let prefix = slug(reference);
    let whole_document = is_whole_document(reference);
    tests.iter().filter(move |t| {
        !whole_document && (t.name == prefix || t.name.starts_with(&format!("{prefix}_")))
    })
}

/// The tests not named after `reference` that cite it, or a subsection of it, in their
/// doc comment: the requirement is proven there indirectly, and the doc comment says how
/// (docs/design/testing.md: the most specific requirement in the name, the others in the
/// doc comment).
fn citing_tests<'a>(reference: &'a str, tests: &'a [Test]) -> impl Iterator<Item = &'a Test> {
    let named: Vec<&str> = named_tests(reference, tests)
        .map(|t| t.name.as_str())
        .collect();
    tests.iter().filter(move |t| {
        !named.contains(&t.name.as_str()) && t.cites.iter().any(|c| within(c, reference))
    })
}

/// The `#[test]` functions in `text`, with the references in their doc comments.
fn tests_in(text: &str) -> Vec<Test> {
    let mut found = Vec::new();
    let mut doc = String::new();
    let mut is_test = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(comment) = line.strip_prefix("///") {
            doc.push_str(comment);
            doc.push(' ');
        } else if line == "#[test]" {
            is_test = true;
        } else if let Some(rest) = line.strip_prefix("fn ").filter(|_| is_test) {
            found.push(Test {
                name: rest.split('(').next().unwrap().to_string(),
                cites: references(&doc),
            });
            doc.clear();
            is_test = false;
        } else if !is_test && !line.starts_with("#[") {
            doc.clear();
        }
    }
    found
}

fn table() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_files(&root.join("src"), &mut sources);
    let mut tests = Vec::new();
    rust_files(&root.join("tests"), &mut tests);

    let mut sites: BTreeMap<String, BTreeSet<(String, usize)>> = BTreeMap::new();
    for file in &sources {
        let text = std::fs::read_to_string(file).unwrap();
        let name = file.strip_prefix(root).unwrap().display().to_string();
        let mut in_test_module = false;
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test") {
                in_test_module = true;
            }
            if in_test_module {
                continue;
            }
            if let Some(comment) = trimmed.strip_prefix("//") {
                for reference in references(comment) {
                    sites
                        .entry(reference)
                        .or_default()
                        .insert((name.clone(), n + 1));
                }
            }
        }
    }

    let mut all_tests = Vec::new();
    for file in sources.iter().chain(&tests) {
        all_tests.extend(tests_in(&std::fs::read_to_string(file).unwrap()));
    }

    let mut out = String::from(
        "# jwz traceability\n\nGenerated by `JWZ_BLESS=1 cargo test -p jwz --test traceability` \
         from the specification references in jwz's source comments and the tests that prove \
         them; the test fails when this file is stale.\n\n\
         A test is listed when it is named after the reference or a subsection of it, or, \
         marked *(cited)*, when its doc comment cites the reference: it proves the requirement \
         indirectly, under the name of a more specific one, and its doc comment says how. A \
         whole document (no section) is traced by its sections.\n\n\
         | Reference | Implemented at | Tests |\n| --- | --- | --- |\n",
    );
    let (mut named_count, mut cited_count, mut whole_count) = (0, 0, 0);
    for (reference, places) in &sites {
        let mut proving: Vec<String> = named_tests(reference, &all_tests)
            .map(|t| format!("`{}`", t.name))
            .collect();
        let named = !proving.is_empty();
        proving
            .extend(citing_tests(reference, &all_tests).map(|t| format!("`{}` *(cited)*", t.name)));
        let sections_traced = is_whole_document(reference)
            && sites
                .keys()
                .any(|r| r != reference && r.starts_with(&format!("{reference} ")));
        let cell = if !proving.is_empty() {
            if named {
                named_count += 1;
            } else {
                cited_count += 1;
            }
            proving.join(", ")
        } else if sections_traced {
            whole_count += 1;
            "whole document: traced by its sections".into()
        } else {
            "–".into()
        };
        let places: Vec<String> = places
            .iter()
            .map(|(file, line)| format!("`{file}:{line}`"))
            .collect();
        let _ = writeln!(out, "| {reference} | {} | {cell} |", places.join(", "));
    }
    let _ = writeln!(
        out,
        "\nOf {} references, {named_count} have a test named after them, {cited_count} are \
         proven by a test that cites them, {whole_count} are whole documents traced by their \
         sections, and {} have no test.",
        sites.len(),
        sites.len() - named_count - cited_count - whole_count
    );
    out
}

#[test]
fn traceability_table_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/traceability.md");
    let current = table();
    if std::env::var_os("JWZ_BLESS").is_some() {
        std::fs::write(&path, &current).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == current,
        "docs/traceability.md is stale: run JWZ_BLESS=1 cargo test -p jwz --test traceability"
    );
}

#[test]
fn references_are_normalized() {
    assert_eq!(references(" RFC 7516 §5.2 step 10: x"), ["RFC 7516 §5.2"]);
    assert_eq!(references(" RFC 7518 Appendix C."), ["RFC 7518 Appendix C"]);
    assert_eq!(
        references(" NIST SP 800-56A §5.8.1 as RFC 7518 §4.6.2"),
        ["NIST SP 800-56A §5.8.1", "RFC 7518 §4.6.2"]
    );
    assert_eq!(slug("RFC 7518 §4.6.2"), "rfc_7518_4_6_2");
    assert_eq!(slug("RFC 7518 Appendix C"), "rfc_7518_appendix_c");
}

#[test]
fn doc_comments_cite_and_subsections_count() {
    let tests = tests_in(
        "/// Also RFC 7518 §4.6.1.1 and\n/// RFC 8725 §3.4.\n#[cfg(x)]\n#[test]\nfn rfc_7518_4_6_2_x() {}\n\
         /// RFC 7516 §2.\nconst X: u8 = 0;\n#[test]\nfn plain() {}",
    );
    assert_eq!(tests.len(), 2);
    assert_eq!(tests[0].cites, ["RFC 7518 §4.6.1.1", "RFC 8725 §3.4"]);
    assert_eq!(tests[1].cites, Vec::<String>::new());
    assert!(within("RFC 7518 §4.6.1.1", "RFC 7518 §4.6.1"));
    assert!(!within("RFC 7518 §4.6.10", "RFC 7518 §4.6.1"));
    assert!(!within("RFC 7518 §4.6", "RFC 7518"));
    assert_eq!(
        citing_tests("RFC 7518 §4.6", &tests)
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        Vec::<&str>::new(),
        "a test named after the reference is not listed twice"
    );
    assert_eq!(citing_tests("RFC 8725 §3.4", &tests).count(), 1);
}
