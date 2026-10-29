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

//! Holds the cores to their rule: no `unsafe`, also not in their dependencies, except the
//! crates approved in `docs/unsafe-exceptions.md` (rust/docs/design.md).
//!
//! For every core, feature set and target that document names, `cargo tree` lists the
//! crates that end up in the program (normal edges, no proc macros, no build scripts).
//! The sources of each crate outside the workspace are parsed with `syn`, and every place
//! that needs `unsafe` is counted: blocks, functions, impls, traits, `extern` blocks, and
//! the keyword inside macro definitions and calls and inside attributes. Code behind any
//! `cfg` counts, so the count errs on the side of more.
//!
//! - `unsafe-audit check`: fails for a crate with `unsafe` that is not listed, a listed
//!   crate in another version than approved (a new version is reviewed again), and an
//!   entry no core needs any more.
//! - `unsafe-audit inventory`: the crates with `unsafe` and their sites, as Markdown.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens as _;
use serde_json::Value;
use syn::visit::{self, Visit};

const LIST: &str = "docs/unsafe-exceptions.md";

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    let result = match mode.as_deref() {
        Some("check") => check(),
        Some("inventory") => inventory(),
        _ => {
            eprintln!("usage: unsafe-audit check|inventory");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("unsafe-audit: {e}");
            ExitCode::from(2)
        }
    }
}

/// The workspace root, where `cargo` resolves the cores.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the tool lives inside the workspace")
        .to_owned()
}

// ---- the list ------------------------------------------------------------------------

struct Policy {
    /// Each core with the features its normal build may enable.
    cores: Vec<(String, Vec<String>)>,
    targets: Vec<String>,
    /// Crate name to the approved versions.
    exceptions: BTreeMap<String, BTreeSet<String>>,
}

fn policy() -> Result<Policy, String> {
    let text = std::fs::read_to_string(root().join(LIST)).map_err(|e| format!("{LIST}: {e}"))?;
    let none = |cell: &str| cell.is_empty() || cell == "–" || cell == "-";
    let cores: Vec<(String, Vec<String>)> = table(&text, "## Cores")?
        .into_iter()
        .map(|row| {
            let features = if none(&row[1]) {
                Vec::new()
            } else {
                row[1].split(',').map(|f| f.trim().to_owned()).collect()
            };
            (row[0].clone(), features)
        })
        .collect();
    let targets: Vec<String> = table(&text, "## Targets")?
        .into_iter()
        .map(|row| row[0].clone())
        .collect();
    if cores.is_empty() || targets.is_empty() {
        return Err(format!("{LIST}: no cores or no targets"));
    }
    let mut exceptions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in table(&text, "## Exceptions")? {
        if row.len() < 4 || row[2].is_empty() || row[3].is_empty() {
            return Err(format!(
                "{LIST}: {} needs a version, a reason and an approval date",
                row[0]
            ));
        }
        exceptions
            .entry(row[0].clone())
            .or_default()
            .insert(row[1].clone());
    }
    Ok(Policy {
        cores,
        targets,
        exceptions,
    })
}

/// The body rows of the first Markdown table after `heading`, cells trimmed and without
/// backticks; none for a table with only its header.
fn table(text: &str, heading: &str) -> Result<Vec<Vec<String>>, String> {
    let start = text
        .lines()
        .position(|line| line.trim() == heading)
        .ok_or_else(|| format!("{LIST}: no section {heading}"))?;
    let rows: Vec<Vec<String>> = text
        .lines()
        .skip(start + 1)
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().replace('`', ""))
                .collect()
        })
        .collect();
    Ok(rows)
}

// ---- the trees -----------------------------------------------------------------------

/// A crate in a tree: name and version.
type Package = (String, String);

struct Tree {
    /// Each crate outside the workspace, with the cores whose tree holds it.
    packages: BTreeMap<Package, BTreeSet<String>>,
    /// Where each crate's sources are, and its build script.
    sources: BTreeMap<Package, (PathBuf, Option<PathBuf>)>,
}

fn cargo(args: &[&str]) -> Result<String, String> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(args)
        .current_dir(root())
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("cargo {}: {e}", args.join(" ")))
}

fn tree(policy: &Policy) -> Result<Tree, String> {
    let metadata: Value =
        serde_json::from_str(&cargo(&["metadata", "--format-version", "1", "--locked"])?)
            .map_err(|e| format!("cargo metadata: {e}"))?;
    let mut sources = BTreeMap::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        if package["source"].is_null() {
            continue;
        }
        let key = (
            package["name"].as_str().unwrap_or_default().to_owned(),
            package["version"].as_str().unwrap_or_default().to_owned(),
        );
        let dir = Path::new(package["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .map(Path::to_owned)
            .unwrap_or_default();
        let build = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.contains(&"custom-build".into()))
            })
            .and_then(|t| t["src_path"].as_str())
            .map(PathBuf::from);
        sources.insert(key, (dir, build));
    }
    let mut packages: BTreeMap<Package, BTreeSet<String>> = BTreeMap::new();
    for (core, features) in &policy.cores {
        let features = features.join(",");
        for target in &policy.targets {
            let mut args = vec![
                "tree",
                "--locked",
                "-p",
                core,
                "-e",
                "normal,no-proc-macro",
                "--no-default-features",
                "--target",
                target,
                "--prefix",
                "none",
                "-f",
                "{p}",
            ];
            if !features.is_empty() {
                args.extend(["--features", &features]);
            }
            for line in cargo(&args)?.lines() {
                let mut words = line.split_whitespace();
                let (Some(name), Some(version)) = (words.next(), words.next()) else {
                    continue;
                };
                let key = (name.to_owned(), version.trim_start_matches('v').to_owned());
                if sources.contains_key(&key) {
                    packages.entry(key).or_default().insert(core.clone());
                }
            }
        }
    }
    Ok(Tree { packages, sources })
}

// ---- the sources ---------------------------------------------------------------------

/// The places a crate needs `unsafe`, by kind.
#[derive(Default)]
struct Sites {
    kinds: BTreeMap<&'static str, usize>,
    files: usize,
    errors: Vec<String>,
}

impl Sites {
    fn total(&self) -> usize {
        self.kinds.values().sum()
    }

    fn describe(&self) -> String {
        let kinds: Vec<String> = self.kinds.iter().map(|(k, n)| format!("{n} {k}")).collect();
        format!(
            "{} in {} files: {}",
            self.total(),
            self.files,
            kinds.join(", ")
        )
    }
}

struct Counter<'a> {
    sites: &'a mut Sites,
    found: usize,
}

impl Counter<'_> {
    fn add(&mut self, kind: &'static str, n: usize) {
        if n > 0 {
            *self.sites.kinds.entry(kind).or_default() += n;
            self.found += n;
        }
    }
}

fn keywords(tokens: TokenStream) -> usize {
    tokens
        .into_iter()
        .map(|token| match token {
            TokenTree::Ident(ident) if ident == "unsafe" => 1,
            TokenTree::Group(group) => keywords(group.stream()),
            _ => 0,
        })
        .sum()
}

impl<'ast> Visit<'ast> for Counter<'_> {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.add("block", 1);
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        self.add(
            "fn",
            usize::from(matches!(node.safety, syn::Safety::Unsafe(_))),
        );
        visit::visit_signature(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.add("impl", usize::from(node.unsafety.is_some()));
        visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.add("trait", usize::from(node.unsafety.is_some()));
        visit::visit_item_trait(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        self.add("extern", 1);
        visit::visit_item_foreign_mod(self, node);
    }

    // Macro bodies are tokens to syn: a keyword there is counted, not understood.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.add("macro", keywords(node.tokens.clone()));
        visit::visit_macro(self, node);
    }

    // `#[unsafe(no_mangle)]`, `#[unsafe(export_name = …)]`.
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        self.add("attribute", keywords(node.meta.to_token_stream()));
        visit::visit_attribute(self, node);
    }
}

/// Every `.rs` file of the crate but its tests, benches, examples and build script.
fn scan(dir: &Path, build: Option<&Path>) -> Sites {
    let mut sites = Sites::default();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            sites
                .errors
                .push(format!("{} cannot be read", next.display()));
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let skip = next == dir
                    && path.file_name().is_some_and(|n| {
                        ["tests", "benches", "examples", "target", "fuzz"]
                            .iter()
                            .any(|s| n == *s)
                    });
                if !skip {
                    pending.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") && Some(path.as_path()) != build {
                count(&path, &mut sites);
            }
        }
    }
    sites
}

fn count(path: &Path, sites: &mut Sites) {
    let parsed = std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|text| syn::parse_file(&text).map_err(|e| e.to_string()));
    match parsed {
        Ok(file) => {
            let mut counter = Counter { sites, found: 0 };
            counter.visit_file(&file);
            if counter.found > 0 {
                sites.files += 1;
            }
        }
        Err(e) => sites.errors.push(format!("{}: {e}", path.display())),
    }
}

fn audit() -> Result<(Policy, Tree, BTreeMap<Package, Sites>), String> {
    let policy = policy()?;
    let tree = tree(&policy)?;
    let sites = tree
        .packages
        .keys()
        .map(|package| {
            let (dir, build) = &tree.sources[package];
            (package.clone(), scan(dir, build.as_deref()))
        })
        .collect();
    Ok((policy, tree, sites))
}

// ---- the modes -----------------------------------------------------------------------

fn check() -> Result<bool, String> {
    let (policy, tree, sites) = audit()?;
    let problems = problems(&policy.exceptions, &tree.packages, &sites);
    for problem in &problems {
        eprintln!("{problem}");
    }
    if problems.is_empty() {
        let listed = sites.values().filter(|s| s.total() > 0).count();
        println!(
            "the cores' trees hold {} crates, {listed} with unsafe, each approved in {LIST}",
            sites.len()
        );
    }
    Ok(problems.is_empty())
}

/// What keeps the trees from passing: unparsed files, crates with `unsafe` that are not
/// listed or not in the approved version, and rows no crate needs.
fn problems(
    exceptions: &BTreeMap<String, BTreeSet<String>>,
    packages: &BTreeMap<Package, BTreeSet<String>>,
    sites: &BTreeMap<Package, Sites>,
) -> Vec<String> {
    let joined = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    let mut problems = Vec::new();
    let mut needed: BTreeSet<&Package> = BTreeSet::new();
    for (package, found) in sites {
        let (name, version) = package;
        for error in &found.errors {
            problems.push(format!("{name} {version}: {error}"));
        }
        if found.total() == 0 {
            continue;
        }
        needed.insert(package);
        match exceptions.get(name) {
            None => problems.push(format!(
                "{name} {version} has unsafe ({}) and is not in {LIST}; in {}",
                found.describe(),
                joined(&packages[package])
            )),
            Some(versions) if !versions.contains(version) => problems.push(format!(
                "{name} {version} is not the approved version ({}): review its unsafe ({}) and update {LIST}",
                joined(versions),
                found.describe()
            )),
            Some(_) => {}
        }
    }
    for (name, versions) in exceptions {
        for version in versions {
            if !needed.contains(&(name.clone(), version.clone())) {
                problems.push(format!(
                    "{name} {version} is in {LIST}, but no core's tree has it with unsafe: remove the row"
                ));
            }
        }
    }
    problems
}

fn inventory() -> Result<bool, String> {
    let (_, tree, sites) = audit()?;
    println!("| Crate | Version | Sites | Cores |");
    println!("|---|---|---|---|");
    for ((name, version), found) in &sites {
        if found.total() == 0 && found.errors.is_empty() {
            continue;
        }
        let cores = &tree.packages[&(name.clone(), version.clone())];
        let mut described = found.describe();
        if !found.errors.is_empty() {
            write!(described, "; {} files not parsed", found.errors.len())
                .expect("writing to a String cannot fail");
        }
        println!(
            "| {name} | {version} | {described} | {} |",
            cores.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    println!();
    println!(
        "{} crates in the cores' trees, {} with unsafe",
        sites.len(),
        sites.values().filter(|s| s.total() > 0).count()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites_of(source: &str) -> Sites {
        let mut sites = Sites::default();
        let file = syn::parse_file(source).expect("test source parses");
        Counter {
            sites: &mut sites,
            found: 0,
        }
        .visit_file(&file);
        sites
    }

    fn package(name: &str, version: &str) -> Package {
        (name.to_owned(), version.to_owned())
    }

    fn tree_with(
        name: &str,
        version: &str,
        source: &str,
    ) -> (
        BTreeMap<Package, BTreeSet<String>>,
        BTreeMap<Package, Sites>,
    ) {
        let key = package(name, version);
        let packages = BTreeMap::from([(key.clone(), BTreeSet::from(["ti-pki".to_owned()]))]);
        let sites = BTreeMap::from([(key, sites_of(source))]);
        (packages, sites)
    }

    fn approved(name: &str, version: &str) -> BTreeMap<String, BTreeSet<String>> {
        BTreeMap::from([(name.to_owned(), BTreeSet::from([version.to_owned()]))])
    }

    #[test]
    fn every_kind_of_unsafe_is_counted_and_comments_and_strings_are_not() {
        let sites = sites_of(
            r#"
            // unsafe in a comment
            const S: &str = "unsafe in a string";
            unsafe fn raw() {}
            fn f() { unsafe { raw() } }
            unsafe impl Send for X {}
            unsafe trait T {}
            extern "C" { fn c(); }
            macro_rules! m { () => { unsafe { raw() } } }
            #[unsafe(no_mangle)]
            fn exported() {}
            "#,
        );
        let kinds: Vec<(&str, usize)> = sites.kinds.iter().map(|(k, n)| (*k, *n)).collect();
        assert_eq!(
            kinds,
            [
                ("attribute", 1),
                ("block", 1),
                ("extern", 1),
                ("fn", 1),
                ("impl", 1),
                ("macro", 1),
                ("trait", 1)
            ]
        );
    }

    #[test]
    fn a_crate_with_unsafe_must_be_listed() {
        let (packages, sites) = tree_with("raw", "1.0.0", "fn f() { unsafe {} }");
        let problems = problems(&BTreeMap::new(), &packages, &sites);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].starts_with("raw 1.0.0 has unsafe"),
            "{problems:?}"
        );
        assert_eq!(
            super::problems(&approved("raw", "1.0.0"), &packages, &sites),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_new_version_of_a_listed_crate_is_reviewed_again() {
        let (packages, sites) = tree_with("raw", "1.1.0", "fn f() { unsafe {} }");
        let problems = problems(&approved("raw", "1.0.0"), &packages, &sites);
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("raw 1.1.0 is not the approved version")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.starts_with("raw 1.0.0 is in")),
            "the old row goes: {problems:?}"
        );
    }

    #[test]
    fn a_row_no_crate_needs_is_removed() {
        let (packages, sites) = tree_with("safe", "1.0.0", "fn f() {}");
        let problems = problems(&approved("safe", "1.0.0"), &packages, &sites);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].ends_with("remove the row"), "{problems:?}");
    }

    #[test]
    fn the_tables_are_read_without_header_and_backticks() {
        let text =
            "## Cores\n\n| Core | Features |\n|---|---|\n| `ti-pki` | load, os |\n\n## Other\n";
        assert_eq!(
            table(text, "## Cores").unwrap(),
            [vec!["ti-pki".to_owned(), "load, os".to_owned()]]
        );
        assert!(table(text, "## Exceptions").is_err());
    }
}
