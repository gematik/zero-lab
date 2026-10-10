//! brainpoolP256r1 in a browser: wasm32-unknown-unknown in headless Chrome. jwz verifies
//! every Go josebp and Python jwcrypto token of the interop fixtures, and makes the same
//! tokens, byte for byte, as natively (`tests/data/interop/jwz.json`). Design time
//! (`just jwz-browser`, stamped): the browser and its driver are not needed by
//! `just check`.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

mod support {
    #[path = "../support/interop.rs"]
    pub mod interop;
}

use std::sync::Arc;

use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jws::{self, Jws};
use jwz::profile::Profile;
use jwz_brainpool::BrainpoolEs256Key;
use support::interop::{jwz_cases, jwz_file, parse_cases, parse_keys, pretty, verify_with_jwz};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[wasm_bindgen_test]
fn jwz_verifies_every_oracle_token() {
    let keys = parse_keys(&json(include_str!("data/interop/keys.json"))).unwrap();
    for file in [
        include_str!("data/interop/go.json"),
        include_str!("data/interop/python.json"),
    ] {
        let (library, cases) = parse_cases(&json(file)).unwrap();
        assert!(!cases.is_empty(), "{library}");
        for case in cases.iter().filter(|case| case.kind == "jws") {
            verify_with_jwz(case, &keys).unwrap_or_else(|e| panic!("{library}, {}: {e}", case.id));
        }
    }
}

#[wasm_bindgen_test]
fn jwz_makes_the_native_tokens() {
    let keys = parse_keys(&json(include_str!("data/interop/keys.json"))).unwrap();
    let current = pretty(&jwz_file(&jwz_cases(&keys).unwrap()));
    assert!(current == include_str!("data/interop/jwz.json"));
}

#[wasm_bindgen_test]
fn epa_es256_on_a_generated_brainpool_key() {
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(RustCrypto::new());
    let key = BrainpoolEs256Key::generate(backend.rng()).unwrap();
    let other = BrainpoolEs256Key::generate(backend.rng()).unwrap();
    assert_ne!(key.public_jwk(), other.public_jwk());
    let token = jws::sign(b"epa", HeaderParams::new(), &key).unwrap();
    let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
    assert_eq!(jws.verify(&key).unwrap().payload(), b"epa");
    let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
    assert!(jws.verify(&other).is_err());
}
