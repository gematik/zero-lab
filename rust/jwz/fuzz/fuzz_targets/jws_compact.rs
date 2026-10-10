//! Any input to `Jws::parse` and, when it parses, to `verify`: errors, never panics.
#![no_main]

use std::sync::{Arc, LazyLock};

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Registry, SignatureAlgorithm};
use jwz::jws::Jws;
use jwz::keys::SoftwareKey;
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static KEY: LazyLock<SoftwareKey<RustCrypto>> = LazyLock::new(|| {
    SoftwareKey::generate(
        SignatureAlgorithm::ES256,
        &REGISTRY,
        Arc::new(RustCrypto::new()),
    )
    .expect("key")
});

fuzz_target!(|token: &str| {
    if let Ok(jws) = Jws::parse(token, &POLICY, &REGISTRY) {
        let _ = jws.header().x5c();
        let _ = jws.header().jwk();
        let _ = jws.verify(&*KEY);
    }
});
