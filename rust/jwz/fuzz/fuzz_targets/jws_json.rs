//! Any input to the JWS JSON parser and `verify`: errors, never panics.
#![no_main]

use std::sync::{Arc, LazyLock};

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Registry, SignatureAlgorithm};
use jwz::jws;
use jwz::keys::SoftwareKey;
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static KEY: LazyLock<SoftwareKey<RustCrypto>> = LazyLock::new(|| {
    SoftwareKey::generate(
        SignatureAlgorithm::EDDSA,
        &REGISTRY,
        Arc::new(RustCrypto::new()),
    )
    .expect("key")
});

fuzz_target!(|text: &str| {
    if let Ok(all) = jws::json::parse(text, &POLICY, &REGISTRY) {
        for jws in all {
            let _ = jws.verify(&*KEY);
        }
    }
});
