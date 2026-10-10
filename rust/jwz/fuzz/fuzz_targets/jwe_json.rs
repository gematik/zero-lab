//! Any input to the JWE JSON parser and `decrypt`: errors, never panics.
#![no_main]

use std::sync::{Arc, LazyLock};

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Curve, Registry};
use jwz::jwe::{self, DecryptionKey};
use jwz::keys::{SoftwareAgreementKey, SymmetricKey};
use jwz::profile::{Policy, Profile};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);
static POLICY: LazyLock<Policy> = LazyLock::new(|| Profile::rfc7518_interop(&REGISTRY).policy);
static BACKEND: LazyLock<Arc<RustCrypto>> = LazyLock::new(|| Arc::new(RustCrypto::new()));
static AGREEMENT: LazyLock<SoftwareAgreementKey<RustCrypto>> = LazyLock::new(|| {
    SoftwareAgreementKey::generate(Curve::P256, Arc::clone(&BACKEND)).expect("key")
});
static SYMMETRIC: LazyLock<SymmetricKey> = LazyLock::new(|| SymmetricKey::new(vec![7; 32]));

fuzz_target!(|text: &str| {
    if let Ok(all) = jwe::json::parse(text, &POLICY, &REGISTRY) {
        for (i, jwe) in all.into_iter().enumerate() {
            let key = if i % 2 == 0 {
                DecryptionKey::Agreement(&*AGREEMENT)
            } else {
                DecryptionKey::Symmetric(&SYMMETRIC)
            };
            let _ = jwe.decrypt(key, BACKEND.as_ref());
        }
    }
});
