# Using jwz

The module documentation explains each part; this guide walks the paths across them.
Every example here is compiled and run by `cargo test --doc`.

## Verify a JWT from an issuer's JWK Set

Three steps, in this order: parse under a profile (the header is checked before any
cryptography), verify with the keys the issuer publishes, then check the claims.

```rust
use std::sync::Arc;

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::Registry;
use jwz::jwk::JwkSet;
use jwz::jws::Jws;
use jwz::jwt::Claims;
use jwz::profile::Profile;
# use jwz::header::HeaderParams;
# use jwz::jwa::SignatureAlgorithm;
# use jwz::keys::SoftwareKey;
# let issuer = SoftwareKey::generate(
#     SignatureAlgorithm::ES256, &Registry::standard(), Arc::new(RustCrypto::new()),
# )?.with_kid("2026-1");
# let jwks = format!(r#"{{"keys":[{}]}}"#, issuer.public_jwk().to_json());
# let token = jwz::jws::sign(
#     br#"{"iss":"https://idp.example","aud":"app","exp":1900000000}"#,
#     HeaderParams::new().typ("JWT"),
#     &issuer,
#     &Profile::strict().policy,
#     &Registry::standard(),
# )?;

let registry = Registry::standard();
let backend = Arc::new(RustCrypto::new());
let profile = Profile::strict();

// From the issuer's jwks_uri; how it is fetched, cached and refreshed is up to you.
let keys = JwkSet::parse(&jwks)?;

let jws = Jws::parse(&token, &profile.policy, &registry)?;
// The set offers the keys with the header's kid that allow signatures and fit the
// accepted algorithm; the signature decides which, if any, signed.
let verified = jws.verify_with(&keys, &registry, &backend)?;

let claims = Claims::parse(verified.payload())?;
let mut rules = profile.claims.clone();
rules.issuer = Some("https://idp.example".into());
rules.audience = Some("app".into());
// The time as the host passes it: any function returning seconds since the epoch.
let now = || 1_800_000_000;
claims.validate(&rules, &now)?;
assert_eq!(claims.iss(), Some("https://idp.example"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The header helps find the key (`kid`), but never chooses its algorithm: the profile
accepted one, and a key is made a verifier for that algorithm only. A JWK whose `alg`
says otherwise, whose `use` or `key_ops` is not for signatures, whose type or curve
does not fit, or whose curve the profile does not list, is passed over. To verify with one key you chose, make it with
`SoftwareKey::from_jwk` and call `Jws::verify`.

### Why jwz never fetches keys

jwz decides which keys may have signed a token and whether one did; where the keys come
from is the host's [`KeyResolver`](crate::jwk::KeyResolver). A server keeps a JWK Set in
memory and refreshes it on its own schedule, a CLI caches it on disk, a browser fetches it
with `fetch` and keeps it in IndexedDB. Each has its own transport, proxy, TLS, cache and
retry rules, and none of that belongs in a token library: it would tie jwz to one HTTP
client and one runtime, and fail the browser. A [`JwkSet`](crate::jwk::JwkSet) is the simplest resolver; a
fetching one implements the trait over the host's cache. Whatever a resolver returns is a
candidate, not trust: a key is never trusted for having been fetched, only its signature
check counts.

### Why time is a function

Time enters jwz only through [`Clock`](crate::jwt::Clock), and every `Fn() -> u64` is
one. The host passes time the same way to every component: `|| now` in a test, its own
clock in a program, `Date.now()` in the browser. A function rather than a value, because a
long-lived component asks again for every token; a function rather than a global, because
a test or a replay must be able to fix it. `SystemClock` and `FixedClock` remain for the
common cases; `SystemClock` does not exist where std has no clock (see below).

## Choose a profile

A [`Profile`](crate::profile::Profile) says what a token may use (`policy`) and what a
JWT must claim (`claims`). Parsing takes the policy, and it is the only place a header is
accepted. Signing and encryption take it too: `jws::sign` and `jwe::encrypt` refuse an
algorithm, a content encryption or a key curve the policy does not list, so a program
never produces a token its own profile would refuse.

- `Profile::strict()` is the default: ES256 on P-256 and EdDSA on Ed25519; ECDH-ES on
  P-256 with A128GCM and A256GCM; no key references (`jku`, `jwk`, `x5u`, `x5c`) in
  tokens; no `crit` extensions; a JWT needs `exp`.
- `Profile::rfc7518_interop(&registry)` allows everything the registry implements. It
  exists for interoperability tests, never for production.
- `ti_jwz::ti()` and `ti_jwz::ti_legacy()` are the gematik TI profiles (crate `ti-jwz`).

A profile is the explicit lists its construction results in. `Profile::new` starts with
no algorithm and strict defaults for everything else; `with` appends the lists of an
[`Algorithms`](crate::profile::Algorithms) bundle. jwz's bundles are constants, each one
RFC 7518 or RFC 8037 construction:

| Constant | Adds |
| --- | --- |
| `ECDSA_NIST` | `ES256`, signing keys on P-256 |
| `EDDSA` | `EdDSA`, signing keys on Ed25519 |
| `HMAC` | `HS256`, `HS384`, `HS512` (available with the feature `hmac`) |
| `ECDH_ES_P256` | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW`, key agreement on P-256 |
| `ECDH_ES_DIRECT_P256` | `ECDH-ES`, key agreement on P-256 |
| `AES_KW` | `A128KW`, `A192KW`, `A256KW` |
| `DIRECT` | `dir` |
| `AES_GCM`, `AES_128_GCM`, `AES_256_GCM` | `A128GCM`, `A192GCM`, `A256GCM`; or one of them |

The curves are lists of their own: a signing key is accepted only on a curve the profile
lists (`signing_curves`), whatever its algorithm, and an ECDH-ES key only on one of the
`key_agreement_curves`. A key states its curve through `JwsKey::curve`; one that states
none is taken to be on its algorithm's registered curve (P-256 for ES256).

```rust
use jwz::jwa::{KeyEncryptionAlgorithm, SignatureAlgorithm};
use jwz::profile::{AES_256_GCM, AES_KW, ECDSA_NIST, Profile};

// Only ES256 on P-256, AES key wrap and A256GCM, and only tokens that say they are
// access tokens (RFC 9068).
let mut mine = Profile::new("access-tokens", 1)
    .with(&ECDSA_NIST)
    .with(&AES_KW)
    .with(&AES_256_GCM);
mine.policy.typ = Some("at+jwt".into());
assert_eq!(mine.policy.signature_algorithms, [SignatureAlgorithm::ES256]);

// strict with AES key wrap added: everything strict accepts, and A128KW.
let wider = Profile::strict().with(&AES_KW);
assert!(wider.policy.key_encryption_algorithms.contains(&KeyEncryptionAlgorithm::A128KW));
```

`with` only appends: a token one profile accepts is accepted by every profile built
from it. A narrower profile is another construction, not a removal.

## Encrypt to a recipient's public key

ECDH-ES needs only the recipient's public JWK. The sender never holds a private key;
the ephemeral key is made and dropped inside `encrypt`.

```rust
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm, Registry};
use jwz::jwe::{self, EncryptionKey, Recipient};
use jwz::jwk::Jwk;
use jwz::profile::Profile;

let public = Jwk::parse(r#"{"kty":"EC","crv":"P-256",
  "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"}"#)?;
// What is per recipient: its algorithm, its key, its header parameters.
let recipient = Recipient {
    alg: KeyEncryptionAlgorithm::ECDH_ES,
    key: EncryptionKey::Public(&public),
    header: HeaderParams::new().cty("JWT"),
};
let token = jwe::encrypt(
    b"for the recipient only",
    ContentEncryptionAlgorithm::A256GCM,
    &recipient,
    &Profile::strict().policy,
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

`ti_jwz::brainpool` does both for brainpoolP256r1, in under 400 lines. Its source is the
worked example. A new name is still refused until a profile allows it: registering
makes a name known, a profile makes it acceptable.

## In the browser

Every jwz crate builds for `wasm32-unknown-unknown`. The RustCrypto backend gets its
random numbers from `Crypto.getRandomValues` without further setup. `just jwz-browser`
runs the round trips and the RFC known answers in headless Chrome.

The browser has no system clock that std can read, so jwz offers no `SystemClock` there
(std would panic on every call). Pass `Date.now()` as the clock:

```rust,ignore
// js_sys::Date::now() is milliseconds since the epoch, as an f64.
let now = || (js_sys::Date::now() / 1000.0) as u64;
claims.validate(&rules, &now)?;
```

Keys come from the issuer's `jwks_uri` through `fetch`, which answers with a JavaScript
promise. jwz's asynchronous traits return futures without a `Send` bound for this reason:
a promise lives on the browser's one thread and its future is not `Send`, so a bound would
shut the browser out. A resolver over `fetch`:

```rust,ignore
use jwz::crypto::asynchronous::BoxFuture;
use jwz::jwk::{AsyncKeyResolver, Jwk, JwkSet};

struct Issuer {
    jwks_uri: String,
}

impl AsyncKeyResolver for Issuer {
    fn resolve_async<'a>(
        &'a self,
        header: &'a jwz::header::Header,
        alg: jwz::jwa::SignatureAlgorithm,
    ) -> BoxFuture<'a, Result<Vec<Jwk>, jwz::Error>> {
        Box::pin(async move {
            // gloo_net or web_sys::Request: the browser's fetch, its cache and CORS rules.
            let text = fetch_text(&self.jwks_uri)
                .await
                // The fetch's own error travels as the source, for the page's log.
                .map_err(|e| {
                    jwz::Error::new(jwz::ErrorCode::KeyUnavailable, "jwks_uri").with_source(e)
                })?;
            let set = JwkSet::parse(&text)?;
            Ok(set.signing_keys(header.kid(), alg).cloned().collect())
        })
    }
}

let verified = jws.verify_with_async(&issuer, &registry, &backend).await?;
```

## Errors

Every failure is a [`jwz::Error`](crate::Error). Its [`code`](crate::Error::code) is a
stable [`ErrorCode`](crate::ErrorCode) to decide on, and its message is for people. An
error never contains key material or token contents, so it can be logged as it is. A
token refused with `PolicyViolation` never reached the cryptography.
