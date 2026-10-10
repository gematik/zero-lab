//! Design-time verification is stamped (`verification/stamps/*.toml`): which check ran,
//! with which tool, with what outcome, over which input files (SHA-256). This test needs
//! none of the tools: it recomputes the hashes and fails when an input changed since the
//! check last ran, so a change to proven code cannot pass `just check` until
//! `just jwz-recheck` has run the proof again.

use std::fmt::Write as _;
use std::path::Path;

use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::HashAlgorithm;

/// `key = "value"` lines, and the `[inputs]` table, of a stamp file.
struct Stamp {
    fields: Vec<(String, String)>,
    inputs: Vec<(String, String)>,
}

fn parse(text: &str) -> Stamp {
    let mut stamp = Stamp {
        fields: Vec::new(),
        inputs: Vec::new(),
    };
    let mut in_inputs = false;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_inputs = line == "[inputs]";
            continue;
        }
        let (key, value) = line.split_once(" = ").expect("key = value");
        let unquote = |s: &str| s.trim().trim_matches('"').to_string();
        let entry = (unquote(key), unquote(value));
        if in_inputs {
            stamp.inputs.push(entry);
        } else {
            stamp.fields.push(entry);
        }
    }
    stamp
}

fn sha256_hex(bytes: &[u8]) -> String {
    let backend = RustCrypto::new();
    let digest = backend
        .hash(HashAlgorithm::Sha256)
        .expect("SHA-256")
        .digest(&[bytes]);
    digest.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn every_stamp_is_fresh_and_passed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("verification/stamps");
    let mut stamps: Vec<_> = std::fs::read_dir(&dir)
        .expect("verification/stamps")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    stamps.sort();
    assert!(!stamps.is_empty());
    for path in stamps {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let stamp = parse(&std::fs::read_to_string(&path).unwrap());
        let field = |key: &str| {
            stamp
                .fields
                .iter()
                .find(|(k, _)| k == key)
                .map_or_else(|| panic!("{name}: no {key}"), |(_, v)| v.as_str())
        };
        assert!(
            field("outcome").starts_with("passed"),
            "{name}: last run did not pass: {}",
            field("outcome")
        );
        assert!(!stamp.inputs.is_empty(), "{name}: no inputs");
        for (file, hash) in &stamp.inputs {
            let bytes = std::fs::read(root.join(file))
                .unwrap_or_else(|e| panic!("{name}: input {file}: {e}"));
            assert_eq!(
                &sha256_hex(&bytes),
                hash,
                "{name}: {file} changed since `{}` last ran: run `just jwz-recheck`",
                field("command")
            );
        }
    }
}
