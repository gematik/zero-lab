# Using jwz

The module documentation explains each part; this guide walks the paths across them.
Every example here is compiled and run by `cargo test --doc`.

## Verify a JWT from an issuer's JWK Set

Three steps, in this order: parse under a profile (the header is checked before any
cryptography), verify with a key you chose, then check the claims. The token's header
helps you find the key (`kid`), but the key decides the algorithm: a key is bound to one
algorithm when you make it, so a header cannot switch it to another.

```rust
use std::sync::Arc;

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{Registry, SignatureAlgorithm};
use jwz::jwk::JwkSet;
use jwz::jws::Jws;
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::SoftwareKey;
use jwz::profile::Profile;
# use jwz::header::HeaderParams;
# let issuer = SoftwareKey::generate(
#     SignatureAlgorithm::ES256, &Registry::standard(), Arc::new(RustCrypto::new()),
# )?.with_kid("2026-1");
# let jwks = format!(r#"{{"keys":[{}]}}"#, issuer.public_jwk().to_json());
# let token = jwz::jws::sign(
#     br#"{"iss":"https://idp.example","aud":"app","exp":1900000000}"#,
#     HeaderParams::new().typ("JWT"),
#     &issuer,
# )?;

let registry = Registry::standard();
let backend = Arc::new(RustCrypto::new());
let profile = Profile::strict();

// From the issuer's jwks_uri; how it is fetched is up to you.
let keys = JwkSet::parse(&jwks)?;

let jws = Jws::parse(&token, &profile.policy, &registry)?;
let kid = jws.header().kid().ok_or("token names no key")?;
let jwk = keys.by_kid(kid).next().ok_or("no key with that kid")?;
let key = SoftwareKey::from_jwk(jwk, SignatureAlgorithm::ES256, &registry, backend)?;
let verified = jws.verify(&key)?;

let claims = Claims::parse(verified.payload())?;
let mut rules = profile.claims.clone();
rules.issuer = Some("https://idp.example".into());
rules.audience = Some("app".into());
// SystemClock in a real program (see "In the browser" below).
claims.validate(&rules, &FixedClock(1_800_000_000))?;
assert_eq!(claims.iss(), Some("https://idp.example"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`SoftwareKey::from_jwk` takes the algorithm from you, not from the JWK: a JWK whose
`alg` says otherwise, or whose curve does not fit, is refused.

## Choose a profile

A [`Profile`](crate::profile::Profile) says what a token may use (`policy`) and what a
JWT must claim (`claims`). Parsing takes the policy, and it is the only place a header is
accepted.

- `Profile::strict()` is the default: ES256 and EdDSA; ECDH-ES on P-256 with AES-GCM; no
  key references (`jku`, `jwk`, `x5u`, `x5c`) in tokens; no `crit` extensions; a JWT
  needs `exp`.
- `Profile::rfc7518_interop(&registry)` allows everything the registry implements. It
  exists for interoperability tests, never for production.
- `ti_jwz::ti()` and `ti_jwz::ti_legacy()` are the gematik TI profiles (crate `ti-jwz`).

Profiles are data. Widen one with another, or narrow one by changing its fields:

```rust
use jwz::jwa::Registry;
use jwz::profile::Profile;

let registry = Registry::standard();
let mut mine = Profile::strict();
// Narrower: only tokens that say they are access tokens (RFC 9068).
mine.policy.typ = Some("at+jwt".into());
// Wider: also accept what another profile accepts.
let both = mine.clone().with(&Profile::rfc7518_interop(&registry));
assert!(both.policy.signature_algorithms.len() > mine.policy.signature_algorithms.len());
```

`with` is a union: a token one profile accepts is accepted by every combination
containing it.

## Encrypt to a recipient's public key

ECDH-ES needs only the recipient's public JWK. The sender never holds a private key;
the ephemeral key is made and dropped inside `encrypt`.

```rust
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm, Registry};
use jwz::jwe::{self, EncryptionKey};
use jwz::jwk::Jwk;

let recipient = Jwk::parse(r#"{"kty":"EC","crv":"P-256",
  "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"}"#)?;
let token = jwe::encrypt(
    b"for the recipient only",
    KeyEncryptionAlgorithm::ECDH_ES,
    ContentEncryptionAlgorithm::A256GCM,
    EncryptionKey::Public(&recipient),
    HeaderParams::new().cty("JWT"),
    &Registry::standard(),
    &RustCrypto::new(),
)?;
assert_eq!(token.split('.').count(), 5);
# Ok::<(), jwz::Error>(())
```

Decryption is in the [`jwe`](crate::jwe) module documentation. It mirrors JWS: parsing
gives a `Jwe<Encrypted>` with a header but no plaintext. `decrypt` gives a
`Jwe<Decrypted>`.

## Keys that never leave an HSM, a KMS or WebCrypto

JWS and JWE only talk to the key traits in [`keys`](crate::keys), so the private key can
live anywhere. A key that answers synchronously implements RustCrypto's
`signature::Signer` and [`JwsKey`](crate::keys::JwsKey). A key that answers
asynchronously implements [`AsyncSigner`](crate::keys::AsyncSigner), and you sign with
`jws::sign_async`. The `keys` module documentation has a complete HSM example. The
`test-util` feature has doubles to test against: `MockHsmSigner` and `TestKmsSigner`.

## Further algorithms and curves

Names are open, and a [`Registry`](crate::jwa::Registry) says which ones a program
knows. Another crate can add an algorithm in two steps:

1. Register its names in a registry; the [`jwa`](crate::jwa) module documentation shows
   how.
2. Give the backend the cryptography. Wrap your backend in
   [`crypto::Extended`](crate::crypto::Extended) and add an `Ecdsa` or `Ecdh` provider
   for the new curve.

`jwz-brainpool` does both for brainpoolP256r1, in under 400 lines. Its source is the
worked example. A new name is still refused until a profile allows it: registering
makes a name known, a profile makes it acceptable.

## In the browser

Every jwz crate builds for `wasm32-unknown-unknown`. The RustCrypto backend gets its
random numbers from `Crypto.getRandomValues` without further setup. `just jwz-browser`
runs the round trips and the RFC known answers in headless Chrome.

The browser has no system clock that std can read, so jwz offers no `SystemClock` there.
Implement [`Clock`](crate::jwt::Clock) over `Date.now()` in your crate:

```rust,ignore
struct BrowserClock;

impl jwz::jwt::Clock for BrowserClock {
    fn now(&self) -> u64 {
        // js_sys::Date::now() is milliseconds since the epoch, as an f64.
        (js_sys::Date::now() / 1000.0) as u64
    }
}
```

## Errors

Every failure is a [`jwz::Error`](crate::Error). Its [`code`](crate::Error::code) is a
stable [`ErrorCode`](crate::ErrorCode) to decide on, and its message is for people. An
error never contains key material or token contents, so it can be logged as it is. A
token refused with `PolicyViolation` never reached the cryptography.
