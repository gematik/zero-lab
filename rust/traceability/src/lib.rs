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

//! The requirement traceability tables of the ti crates (docs/design/testing.md, "Tests
//! name the requirement they prove"): every requirement a crate's source cites in a
//! comment, where it is cited, and the tests that prove it.
//!
//! A crate calls [`assert_current`] from its `tests/traceability.rs`; the test fails when
//! the committed `docs/traceability.md` differs from what the sources say, and
//! `TRACE_BLESS=1 cargo test -p <crate> --test traceability` rewrites it.
//!
//! References, most specific kind first:
//!
//! - a rule of this repository's specifications (`P12-036`, `TSLDET-013`, `PATH-001`), which
//!   must exist in `spec/`;
//! - a gematik requirement: an afo (`A_28419`, `GS-A_4898`, `TIP1-A_4108`; an afo's version
//!   suffix `-01` is dropped), a use case (`TUC_PKI_006`) or a table (`Tab_PKI_405`);
//! - an RFC, its section or appendix (`RFC 7292 §4.2`, `RFC 7292 Appendix B.2`; the bare
//!   `RFC 7292 B.2` is read as the appendix);
//! - a standard section (`ETSI TS 119 612 §5.3`, `NIST SP 800-56A §5.8.1`).
//!
//! A test proves a reference when it is named after it or a subsection of it
//! (`p12_036_…`, `tuc_pki_006_8a_…`, `rfc_7292_4_2_…`) or cites it in its doc comment, the
//! place for the requirements after the first. A whole document (`RFC 7292`) names no test:
//! every test of it would match. Tests named like a requirement that no row of the table
//! takes are listed below it, so a name without a citing source shows.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The rule prefixes of the specifications under `spec/`.
const SPEC_PREFIXES: &[&str] = &[
    "BUNDLE", "IDPV", "OCSP", "P12", "PATH", "PROF", "ROOTS", "TSLDET", "TSLSIG", "VALID",
];

/// The kind of a reference; the table lists the kinds in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A rule of a specification under `spec/`.
    Spec,
    /// A gematik afo, use case or table.
    Gematik,
    /// An RFC, a section or an appendix of one.
    Rfc,
    /// A section of another standard.
    Standard,
}

/// A reference in normal form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    /// Its kind.
    pub kind: Kind,
    /// Its normal form: `P12-036`, `A_28419`, `TUC_PKI_006`, `RFC 7292 §4.2`.
    pub text: String,
}

impl Reference {
    fn new(kind: Kind, text: String) -> Self {
        Self { kind, text }
    }

    /// The test-name prefix it maps to: `p12_036`, `gs_a_4898`, `rfc_7292_appendix_b_2`.
    pub fn slug(&self) -> String {
        let mut slug = String::new();
        for c in self.text.to_lowercase().chars() {
            if c.is_ascii_alphanumeric() {
                slug.push(c);
            } else if !slug.ends_with('_') {
                slug.push('_');
            }
        }
        slug.trim_matches('_').to_string()
    }

    /// A whole document, which names no tests.
    fn is_whole_document(&self) -> bool {
        matches!(self.kind, Kind::Rfc | Kind::Standard)
            && !self.text.contains('§')
            && !self.text.contains("Appendix")
    }

    /// Whether `test` is named after this reference or a subsection of it.
    fn names(&self, test: &str) -> bool {
        if self.is_whole_document() {
            return false;
        }
        let slug = self.slug();
        test == slug
            || test
                .strip_prefix(&slug)
                .is_some_and(|rest| rest.starts_with('_'))
    }
}

fn is_digits(s: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&s.len()) && s.chars().all(|c| c.is_ascii_digit())
}

/// A section number after `§`, or an appendix such as `B.2`: digits and dots, trailing
/// dots dropped.
fn section_number(word: &str) -> Option<String> {
    let s: String = word
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let s = s.trim_end_matches('.');
    (!s.is_empty() && s.starts_with(|c: char| c.is_ascii_digit())).then(|| s.to_string())
}

/// An appendix name: a capital letter, optionally followed by `.` and a section number.
fn appendix(word: &str) -> Option<String> {
    let word = word.trim_end_matches('.');
    let mut chars = word.chars();
    let letter = chars.next().filter(char::is_ascii_uppercase)?;
    let rest = chars.as_str();
    if rest.is_empty() {
        return Some(letter.to_string());
    }
    let number = section_number(rest.strip_prefix('.')?)?;
    (number.len() == rest.len() - 1).then(|| format!("{letter}.{number}"))
}

/// What follows a document number: `§4.2`, `section 4.2`, `Appendix B.2` or `B.2`.
fn part(words: &[&str], i: usize) -> Option<String> {
    let word = *words.get(i)?;
    if let Some(s) = word.strip_prefix('§') {
        return section_number(s).map(|s| format!(" §{s}"));
    }
    if word.eq_ignore_ascii_case("section") {
        return section_number(words.get(i + 1)?).map(|s| format!(" §{s}"));
    }
    if word.eq_ignore_ascii_case("appendix") {
        return appendix(words.get(i + 1)?).map(|a| format!(" Appendix {a}"));
    }
    // The bare appendix (`RFC 7292 B.2`) only with a section number: a single capital
    // letter after an RFC number is too often an ordinary word.
    appendix(word)
        .filter(|a| a.contains('.'))
        .map(|a| format!(" Appendix {a}"))
}

fn gematik(word: &str) -> Option<String> {
    let afo = |w: &str| {
        let w = w.strip_prefix("A_")?;
        let number = w.split('-').next()?;
        let version = &w[number.len()..];
        (is_digits(number, 4..=5)
            && (version.is_empty()
                || version
                    .strip_prefix('-')
                    .is_some_and(|v| is_digits(v, 2..=2))))
        .then(|| format!("A_{number}"))
    };
    if let Some(a) = afo(word) {
        return Some(a);
    }
    for prefix in ["GS-", "TIP1-"] {
        if let Some(a) = word.strip_prefix(prefix).and_then(afo) {
            return Some(format!("{prefix}{a}"));
        }
    }
    let mut parts = word.split('_');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("TUC"), Some(area), Some(n))
            if area.chars().all(|c| c.is_ascii_uppercase()) && is_digits(n, 3..=3) =>
        {
            parts.next().is_none().then(|| word.to_string())
        }
        (Some("Tab"), Some(area), Some(n))
            if area.chars().all(|c| c.is_ascii_uppercase()) && is_digits(n, 1..=4) =>
        {
            parts.all(|p| is_digits(p, 1..=3)).then(|| word.to_string())
        }
        _ => None,
    }
}

fn spec_rule(word: &str) -> Option<String> {
    let (prefix, number) = word.split_once('-')?;
    (SPEC_PREFIXES.contains(&prefix) && is_digits(number, 3..=3)).then(|| word.to_string())
}

/// The references in a comment, in the order they appear.
pub fn references(comment: &str) -> Vec<Reference> {
    let words: Vec<&str> = comment
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ',' | ';'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | ':'
                        | '`'
                        | '"'
                        | '\''
                        | '*'
                        | '/'
                        | '<'
                        | '>'
                )
        })
        .map(|w| w.trim_end_matches(['.', '-']))
        .filter(|w| !w.is_empty())
        .collect();
    let mut found = Vec::new();
    for (i, word) in words.iter().enumerate() {
        if let Some(rule) = spec_rule(word) {
            found.push(Reference::new(Kind::Spec, rule));
        } else if let Some(id) = gematik(word) {
            found.push(Reference::new(Kind::Gematik, id));
        } else if let Some((number, next)) = word
            .strip_prefix("RFC")
            .and_then(|n| {
                if n.is_empty() {
                    words.get(i + 1).map(|n| (*n, i + 2))
                } else {
                    Some((n, i + 1))
                }
            })
            .filter(|(n, _)| is_digits(n, 3..=4))
        {
            let part = part(&words, next).unwrap_or_default();
            found.push(Reference::new(Kind::Rfc, format!("RFC {number}{part}")));
        } else if *word == "ETSI"
            && let (Some(series), Some(a), Some(b)) =
                (words.get(i + 1), words.get(i + 2), words.get(i + 3))
            && matches!(*series, "TS" | "EN" | "TR")
            && is_digits(a, 3..=3)
            && is_digits(b, 3..=3)
        {
            let part = part(&words, i + 4).unwrap_or_default();
            found.push(Reference::new(
                Kind::Standard,
                format!("ETSI {series} {a} {b}{part}"),
            ));
        } else if *word == "SP"
            && i >= 1
            && words[i - 1] == "NIST"
            && let Some(number) = words.get(i + 1)
            && number.starts_with("800-")
        {
            let part = part(&words, i + 2).unwrap_or_default();
            found.push(Reference::new(
                Kind::Standard,
                format!("NIST SP {number}{part}"),
            ));
        }
    }
    found
}

/// Whether a test name starts like a requirement, so that one no row takes is listed.
fn looks_like_a_requirement(test: &str) -> bool {
    let mut parts = test.split('_');
    let first = parts.next().unwrap_or_default();
    let second = parts.next().unwrap_or_default();
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    SPEC_PREFIXES
        .iter()
        .any(|p| p.eq_ignore_ascii_case(first) && digits(second))
        || (first == "a" && digits(second))
        || (first == "rfc" && digits(second))
        || matches!(first, "tuc" | "tab" | "gs" | "tip1" | "etsi")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.map(|e| e.unwrap().path()) {
        if path.is_dir() {
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// The comment on a line: a whole-line comment, or one after code that holds no string.
fn comment(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if let Some(c) = trimmed.strip_prefix("//") {
        return Some(c);
    }
    let at = line.find(" // ")?;
    (!line[..at].contains('"')).then(|| &line[at + 3..])
}

/// Whether `lines` start with a `#[cfg(test)]` (or `#[cfg(all(test, …))]`) inline module.
fn opens_a_test_module(lines: &[&str]) -> bool {
    let first = lines[0].trim_start();
    if !(first.starts_with("#[cfg(test)]") || first.starts_with("#[cfg(all(test")) {
        return false;
    }
    lines[1..]
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.starts_with("#[") && !l.is_empty())
        .is_some_and(|l| {
            l.trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ")
                .starts_with("mod ")
                && l.ends_with('{')
        })
}

/// Spec rules the code names in a string literal (`"TSLDET-002"`): the rule a result
/// reports.
fn rule_literals(line: &str) -> impl Iterator<Item = Reference> + '_ {
    line.split('"')
        .skip(1)
        .step_by(2)
        .filter_map(spec_rule)
        .map(|rule| Reference::new(Kind::Spec, rule))
}

/// A test: its name and the references its doc comment cites.
struct Test {
    name: String,
    cites: Vec<Reference>,
}

const TEST_ATTRIBUTES: &[&str] = &["#[test]", "#[wasm_bindgen_test]"];

fn tests_in(text: &str, out: &mut Vec<Test>) {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for (i, line) in lines.iter().enumerate() {
        if !TEST_ATTRIBUTES.contains(line) {
            continue;
        }
        let mut docs = Vec::new();
        for above in lines[..i].iter().rev() {
            if let Some(doc) = above.strip_prefix("///") {
                docs.extend(references(doc));
            } else if !above.starts_with("#[") {
                break;
            }
        }
        let name = lines[i + 1..].iter().find_map(|l| {
            let l = l.strip_prefix("async ").unwrap_or(l);
            l.strip_prefix("fn ")
                .map(|rest| rest.split(['(', '<']).next().unwrap().to_string())
        });
        if let Some(name) = name {
            out.push(Test { name, cites: docs });
        }
    }
}

fn spec_rules(spec: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    markdown_files(spec, &mut files);
    assert!(
        !files.is_empty(),
        "no specification found in {}",
        spec.display()
    );
    files
        .iter()
        .flat_map(|f| references(&std::fs::read_to_string(f).unwrap()))
        .filter(|r| r.kind == Kind::Spec)
        .map(|r| r.text)
        .collect()
}

/// The table for the crate in `manifest_dir`, from the comments in `src/` outside test
/// modules and the tests in `src/` and `tests/`.
///
/// # Panics
///
/// On an unreadable source file, and when a source cites a spec rule that `spec/` does not
/// define.
pub fn table(manifest_dir: &Path, crate_name: &str) -> String {
    let mut sources = Vec::new();
    rust_files(&manifest_dir.join("src"), &mut sources);
    let mut test_files = Vec::new();
    rust_files(&manifest_dir.join("tests"), &mut test_files);

    let sites = citations(manifest_dir, &sources);
    let spec = manifest_dir.join("../../spec");
    let known = spec_rules(&spec);
    let unknown: Vec<&str> = sites
        .keys()
        .filter(|r| r.kind == Kind::Spec && !known.contains(&r.text))
        .map(|r| r.text.as_str())
        .collect();
    assert!(
        unknown.is_empty(),
        "{crate_name} cites rules that spec/ does not define: {}",
        unknown.join(", ")
    );

    let mut tests = Vec::new();
    for file in sources.iter().chain(&test_files) {
        tests_in(&std::fs::read_to_string(file).unwrap(), &mut tests);
    }
    render(crate_name, &sites, &tests)
}

/// Where each reference is cited: file relative to `manifest_dir`, line.
type Sites = BTreeMap<Reference, BTreeSet<(String, usize)>>;

fn citations(manifest_dir: &Path, sources: &[PathBuf]) -> Sites {
    let mut sites = Sites::new();
    for file in sources {
        let text = std::fs::read_to_string(file).unwrap();
        let name = file
            .strip_prefix(manifest_dir)
            .unwrap()
            .display()
            .to_string()
            .replace('\\', "/");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            // Test modules come last in a file; what they cite is not an implementation.
            if opens_a_test_module(&lines[n..]) {
                break;
            }
            let cited = comment(line)
                .map(references)
                .unwrap_or_default()
                .into_iter()
                .chain(rule_literals(line));
            for reference in cited {
                sites
                    .entry(reference)
                    .or_default()
                    .insert((name.clone(), n + 1));
            }
        }
    }
    sites
}

fn render(crate_name: &str, sites: &Sites, tests: &[Test]) -> String {
    let proving = |reference: &Reference| -> Vec<&str> {
        let mut names: Vec<&str> = tests
            .iter()
            .filter(|t| reference.names(&t.name) || t.cites.contains(reference))
            .map(|t| t.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    };

    let mut out = format!(
        "# {crate_name} traceability\n\nGenerated by `TRACE_BLESS=1 cargo test -p {crate_name} \
         --test traceability` from the requirement references in {crate_name}'s source \
         comments and the tests named after them or citing them in their doc comment; the \
         test fails when this file is stale.\n\n\
         | Reference | Cited at | Tests |\n| --- | --- | --- |\n"
    );
    let mut traced = BTreeSet::new();
    let mut covered = 0;
    for (reference, places) in sites {
        let named = proving(reference);
        traced.extend(named.iter().copied());
        if !named.is_empty() {
            covered += 1;
        }
        let places: Vec<String> = places
            .iter()
            .map(|(file, line)| format!("`{file}:{line}`"))
            .collect();
        let named: Vec<String> = named.iter().map(|t| format!("`{t}`")).collect();
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            reference.text,
            places.join(", "),
            if named.is_empty() {
                "–".into()
            } else {
                named.join(", ")
            }
        );
    }
    let _ = writeln!(
        out,
        "\n{covered} of {} references have a test named after them or citing them; a whole \
         document names none, and the rest are covered by tests of the enclosing section or \
         of the behaviour.",
        sites.len()
    );

    let mut untraced: Vec<&str> = tests
        .iter()
        .map(|t| t.name.as_str())
        .filter(|t| looks_like_a_requirement(t) && !traced.contains(t))
        .collect();
    untraced.sort_unstable();
    untraced.dedup();
    if !untraced.is_empty() {
        let _ = writeln!(
            out,
            "\n## Tests named after a requirement the source does not cite\n"
        );
        for t in untraced {
            let _ = writeln!(out, "- `{t}`");
        }
    }
    out
}

/// Fails when `docs/traceability.md` of the crate in `manifest_dir` is stale; with
/// `TRACE_BLESS` set, rewrites it first.
///
/// # Panics
///
/// When the committed table differs from the generated one, and as [`table`] does.
pub fn assert_current(manifest_dir: &str, crate_name: &str) {
    let root = Path::new(manifest_dir);
    let path = root.join("docs/traceability.md");
    let current = table(root, crate_name);
    if std::env::var_os("TRACE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &current).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == current,
        "{crate_name}/docs/traceability.md is stale: run TRACE_BLESS=1 cargo test -p \
         {crate_name} --test traceability"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(comment: &str) -> Vec<String> {
        references(comment).into_iter().map(|r| r.text).collect()
    }

    #[test]
    fn spec_rules_are_recognised_by_their_prefix() {
        assert_eq!(
            texts(" P12-036: the limit; TSLSIG-040/043, SHA-256 and AES-128."),
            ["P12-036", "TSLSIG-040"]
        );
    }

    #[test]
    fn gematik_references_drop_the_afo_version() {
        assert_eq!(
            texts(
                " gemSpec_PKI A_23142-01, GS-A_4898 and TIP1-A_4108; TUC_PKI_006 step 8a, Tab_PKI_252_01."
            ),
            [
                "A_23142",
                "GS-A_4898",
                "TIP1-A_4108",
                "TUC_PKI_006",
                "Tab_PKI_252_01"
            ]
        );
    }

    #[test]
    fn rfc_sections_and_appendices_are_normalised() {
        assert_eq!(
            texts(" RFC 7292 §4.2). RFC 7292 B.4, RFC 6960 appendix A.1, RFC 7292 Appendix C: x"),
            [
                "RFC 7292 §4.2",
                "RFC 7292 Appendix B.4",
                "RFC 6960 Appendix A.1",
                "RFC 7292 Appendix C"
            ]
        );
        assert_eq!(
            texts(" RFC 3339, UTC; RFC3161 tokens"),
            ["RFC 3339", "RFC 3161"]
        );
        assert_eq!(texts(" RFC 5280 section 4.2.1.9."), ["RFC 5280 §4.2.1.9"]);
    }

    #[test]
    fn standards_are_recognised() {
        assert_eq!(
            texts(" ETSI TS 119 612 §5.3 and NIST SP 800-56A §5.8.1"),
            ["ETSI TS 119 612 §5.3", "NIST SP 800-56A §5.8.1"]
        );
    }

    #[test]
    fn slugs_are_test_name_prefixes() {
        let slug = |c: &str| references(c).remove(0).slug();
        assert_eq!(slug("P12-036"), "p12_036");
        assert_eq!(slug("GS-A_4898"), "gs_a_4898");
        assert_eq!(slug("TUC_PKI_006"), "tuc_pki_006");
        assert_eq!(slug("RFC 7292 Appendix B.2"), "rfc_7292_appendix_b_2");
        assert_eq!(slug("RFC 7518 §4.6.2"), "rfc_7518_4_6_2");
    }

    #[test]
    fn a_test_is_named_after_a_reference_or_its_subsection() {
        let r = references("RFC 7292 §4").remove(0);
        assert!(r.names("rfc_7292_4_2_bags"));
        assert!(!r.names("rfc_7292_40_bags"));
        assert!(!references("RFC 7292").remove(0).names("rfc_7292_bags"));
        assert!(
            references("TSLDET-013")
                .remove(0)
                .names("tsldet_013_refetch")
        );
    }

    #[test]
    fn tests_are_found_with_their_doc_citations() {
        let mut found = Vec::new();
        tests_in(
            "/// Also P12-030.\n#[test]\n#[ignore = \"x\"]\nfn p12_036_x() {}\n\
             #[wasm_bindgen_test]\nasync fn plain() {}\n",
            &mut found,
        );
        assert_eq!(found[0].name, "p12_036_x");
        assert_eq!(found[0].cites[0].text, "P12-030");
        assert_eq!(found[1].name, "plain");
    }

    #[test]
    fn trailing_comments_are_read_but_not_inside_strings() {
        assert_eq!(comment("let x = 1; // RFC 1234"), Some(" RFC 1234"));
        assert_eq!(comment("let u = \"http://x // y\";"), None);
    }

    #[test]
    fn only_an_inline_test_module_ends_the_sources() {
        assert!(opens_a_test_module(&["#[cfg(test)]", "mod tests {"]));
        assert!(opens_a_test_module(&[
            "#[cfg(all(test, feature = \"x\"))]",
            "",
            "mod t {"
        ]));
        assert!(!opens_a_test_module(&[
            "#[cfg(test)]",
            "use std::path::Path;"
        ]));
        assert!(!opens_a_test_module(&["#[cfg(test)]", "mod testing;"]));
        assert!(!opens_a_test_module(&[
            "    #[cfg(test)]",
            "    pub(crate) fn with(self) {"
        ]));
    }

    #[test]
    fn rules_named_in_string_literals_are_citations() {
        let found: Vec<String> = rule_literals(r#"(Code::X, "TSLSIG-032"), "SHA-256", "x""#)
            .map(|r| r.text)
            .collect();
        assert_eq!(found, ["TSLSIG-032"]);
    }

    #[test]
    fn requirement_like_names_are_recognised() {
        assert!(looks_like_a_requirement("tsldet_013_x"));
        assert!(looks_like_a_requirement("tuc_pki_006_x"));
        assert!(looks_like_a_requirement("a_28419_x"));
        assert!(!looks_like_a_requirement("path_is_walked"));
        assert!(!looks_like_a_requirement("a_signer_passes"));
    }
}
