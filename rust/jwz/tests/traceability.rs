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

/// The tests named after `reference` or a subsection of it. A whole document (`RFC
/// 7515` without a section) names no tests: every test of it would match.
fn named_tests<'a>(reference: &str, tests: &'a [String]) -> impl Iterator<Item = &'a String> {
    let prefix = slug(reference);
    let whole_document = !reference.contains('§') && !reference.contains("Appendix");
    tests
        .iter()
        .filter(move |t| !whole_document && (**t == prefix || t.starts_with(&format!("{prefix}_"))))
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

    let mut test_names = Vec::new();
    for file in sources.iter().chain(&tests) {
        let text = std::fs::read_to_string(file).unwrap();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if line.trim() == "#[test]" {
                for next in lines.by_ref() {
                    if let Some(rest) = next.trim().strip_prefix("fn ") {
                        test_names.push(rest.split('(').next().unwrap().to_string());
                        break;
                    }
                }
            }
        }
    }

    let mut out = String::from(
        "# jwz traceability\n\nGenerated by `JWZ_BLESS=1 cargo test -p jwz --test traceability` \
         from the specification references in jwz's source comments and the tests named \
         after them; the test fails when this file is stale.\n\n\
         | Reference | Implemented at | Tests |\n| --- | --- | --- |\n",
    );
    for (reference, places) in &sites {
        let named: Vec<String> = named_tests(reference, &test_names)
            .map(|t| format!("`{t}`"))
            .collect();
        let places: Vec<String> = places
            .iter()
            .map(|(file, line)| format!("`{file}:{line}`"))
            .collect();
        let _ = writeln!(
            out,
            "| {reference} | {} | {} |",
            places.join(", "),
            if named.is_empty() {
                "–".into()
            } else {
                named.join(", ")
            }
        );
    }
    let covered = sites
        .keys()
        .filter(|r| named_tests(r, &test_names).next().is_some())
        .count();
    let _ = writeln!(
        out,
        "\n{covered} of {} references have a test named after them; the rest are covered by \
         tests of the enclosing section or of the behaviour.",
        sites.len()
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
