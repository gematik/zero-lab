//! Brainpool interoperability with Go josebp and Python jwcrypto, from the fixtures in
//! `tests/data/interop` (made at design time by `just jwz-interop`; see
//! `interop/README.md`). Needs neither oracle: it checks that jwz verifies every oracle
//! token, that every oracle accepted jwz's current tokens, and that the coverage table
//! is current.

mod support {
    #[path = "../support/interop.rs"]
    pub mod interop;
}

use support::interop::{
    ORACLES, coverage, data_dir, jwz_cases, jwz_file, pretty, read_cases, read_keys, read_verdicts,
    sha256_hex, verify_with_jwz,
};

#[test]
fn jwz_verifies_every_oracle_token() {
    let keys = read_keys(&data_dir().join("keys.json")).unwrap();
    for oracle in ORACLES {
        let (library, cases) = read_cases(&data_dir().join(format!("{oracle}.json"))).unwrap();
        assert!(!cases.is_empty(), "{oracle}");
        for case in &cases {
            verify_with_jwz(case, &keys).unwrap_or_else(|e| panic!("{library}, {}: {e}", case.id));
        }
    }
}

#[test]
fn jwz_tokens_are_the_ones_the_oracles_checked() {
    // jwz's tokens are deterministic: a change in jwz's output shows here, until
    // `just jwz-interop` has the oracles check the new tokens.
    let keys = read_keys(&data_dir().join("keys.json")).unwrap();
    let committed = std::fs::read_to_string(data_dir().join("jwz.json")).unwrap();
    let current = pretty(&jwz_file(&jwz_cases(&keys).unwrap()));
    assert!(
        committed == current,
        "jwz's tokens changed: run `just jwz-interop`"
    );
}

#[test]
fn every_oracle_accepted_jwz_tokens() {
    let source = std::fs::read(data_dir().join("jwz.json")).unwrap();
    let (_, cases) = read_cases(&data_dir().join("jwz.json")).unwrap();
    let mut accepted_by = vec![0; cases.len()];
    for oracle in ORACLES {
        let verdicts = read_verdicts(&data_dir().join(format!("{oracle}-verdicts.json"))).unwrap();
        assert_eq!(
            verdicts.source,
            sha256_hex(&source),
            "{oracle} checked another jwz.json: run `just jwz-interop`"
        );
        for (i, case) in cases.iter().enumerate() {
            let result = verdicts
                .results
                .get(&case.id)
                .unwrap_or_else(|| panic!("{oracle}: no verdict on {}", case.id));
            assert!(
                result == "ok" || result.starts_with("skipped: "),
                "{} ({oracle}) on {}: {result}",
                verdicts.library,
                case.id
            );
            if result == "ok" {
                accepted_by[i] += 1;
            }
        }
    }
    for (case, count) in cases.iter().zip(accepted_by) {
        assert!(count > 0, "no oracle accepted {}", case.id);
    }
}

#[test]
fn coverage_table_is_current() {
    let committed = std::fs::read_to_string(data_dir().join("COVERAGE.md")).unwrap();
    assert!(
        committed == coverage(&data_dir()).unwrap(),
        "COVERAGE.md is stale: run `just jwz-interop`"
    );
}
