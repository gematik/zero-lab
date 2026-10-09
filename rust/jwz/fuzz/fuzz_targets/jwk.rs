//! Any input to JWK and JWK Set parsing, `check`, `public`, serialization and the
//! thumbprint: errors, never panics; a parsed key survives its own serialization.
#![no_main]

use std::sync::LazyLock;

use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{HashAlgorithm, Registry};
use jwz::jwk::{Jwk, JwkSet};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static BACKEND: LazyLock<RustCrypto> = LazyLock::new(RustCrypto::new);

fuzz_target!(|text: &str| {
    if let Ok(jwk) = Jwk::parse(text) {
        let _ = jwk.check(&REGISTRY);
        let _ = jwk.public();
        let again = Jwk::parse(&jwk.to_json()).expect("a parsed key reparses");
        assert_eq!(again, jwk);
        if let Some(sha256) = BACKEND.hash(HashAlgorithm::Sha256) {
            let _ = jwk.thumbprint(sha256);
        }
    }
    let _ = JwkSet::parse(text);
});
