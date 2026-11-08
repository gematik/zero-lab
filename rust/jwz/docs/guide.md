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

- `Profile::strict()` is the default: ES256 on P-256 and Ed25519 (RFC 9864); ECDH-ES on
  P-256 with A128GCM and A256GCM; no key references (`jku`, `jwk`, `x5u`, `x5c`) in
  tokens; no `crit` extensions; a JWT needs `exp`.
- `Profile::rfc7518_interop(&registry)` allows everything the registry implements. It
  exists for interoperability tests, never for production.
- `ti_jwz::ti()` and `ti_jwz::ti_legacy()` are the gematik TI profiles (crate `ti-jwz`).

A profile is the explicit lists its construction results in. `Profile::new` starts with
no algorithm and strict defaults for everything else; `with` appends the lists of an
[`Algorithms`](crate::profile::Algorithms) bundle. jwz's bundles are constants, each one
RFC 7518, RFC 8037 or RFC 9864 construction:

| Constant | Adds |
| --- | --- |
| `ECDSA_NIST` | `ES256`, signing keys on P-256 |
| `ED25519` | `Ed25519` (RFC 9864), signing keys on Ed25519 |
| `EDDSA` | the polymorphic `EdDSA` (RFC 8037, deprecated by RFC 9864), signing keys on Ed25519; for older peers only |
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

## RFC 8725: what jwz does and what is yours

RFC 8725, the JSON Web Token Best Current Practices, asks things of libraries and of
applications. jwz meets what a library can. What needs knowledge only the application has
(which issuers and subjects it trusts, which audience it is, which kinds of token it
takes) is yours, and jwz gives it a place: a [`Profile`](crate::profile::Profile), its
[`ClaimsPolicy`](crate::profile::ClaimsPolicy), a
[`KeyResolver`](crate::jwk::KeyResolver). Each section is proven by the tests named
`rfc_8725_3_<n>_…`; the code that meets it cites it, and `docs/traceability.md` lists
both.

| § | Requirement | jwz | Yours |
| --- | --- | --- | --- |
| 3.1 | The caller sets the algorithms, and no other is used | The profile's lists are the only algorithms jwz parses, verifies, signs or encrypts with; a name matches only exactly | Build the profile from the bundles you need (`Profile::new`, `with`) |
| 3.1 | `alg` and `enc` are the algorithms used | The algorithm is the one the policy accepted from the header, and a key is made a verifier for it alone | – |
| 3.1 | Each key is used with exactly one algorithm, checked when used | A JWS key states its one algorithm, checked at every verification; a JWK or shared key published with an `alg` is used for that algorithm only | Publish keys with `alg`: a key without one is bound by its type, its curve and your profile, which may list several algorithms for it (HS256 and HS512; `dir` and AES key wrap; ECDH-ES with and without key wrap) |
| 3.2 | Only current algorithms; agility | `strict` lists ES256, Ed25519, ECDH-ES on P-256 and AES-GCM; RSA PKCS #1 v1.5 encryption is not implemented; a new algorithm comes through the registry and a profile | Choose your profile and revise it; `rfc7518-interop` never in production |
| 3.2 | No `none` unless the caller asks | `none` can be neither parsed, registered nor signed, whatever the caller asks | – |
| 3.2 | Deterministic ECDSA | ES256 signs with RFC 6979 nonces | A signer of yours (HSM, KMS) uses nonces of its own |
| 3.3 | Every cryptographic operation validated, each layer of a Nested JWT | A JWS has a payload only after its signature verifies, a JWE a plaintext only after its tag | A Nested JWT: parse the plaintext as a JWS under its own profile and verify it with its issuer's key; jwz does not follow `cty` |
| 3.4 | Cryptographic inputs validated | An `epk` must be on the recipient key's curve, and the point is validated on it before the key agreement | A backend of yours (`crypto::Extended`) validates its points as well |
| 3.5 | Keys with sufficient entropy; no password as an HMAC key | Generated keys come from the backend's random source; an HMAC key shorter than its hash is refused; no PBES2 | Key material you bring comes from a random source, never from a password |
| 3.6 | No compression before encryption | `zip` is neither produced nor accepted | – |
| 3.7 | UTF-8 only | Headers, claims and JWKs are UTF-8 JSON; other bytes, a byte order mark and a lone surrogate are refused | – |
| 3.8 | The keys belong to `iss`; `sub` is valid | `verify_with` takes the keys your resolver offers, never keys the token points at; `ClaimsPolicy::issuer` holds `iss` to one issuer | Resolve the keys of the issuer you expect (its `jwks_uri`) and set `issuer` to it; check `sub` (`Claims::sub`) against your subjects |
| 3.9 | `aud` present and checked | `ClaimsPolicy::audience` refuses a token without `aud` or whose `aud` does not contain it | Set `audience` whenever an issuer serves more than one recipient |
| 3.10 | `kid`, `jku` and `x5u` are untrusted input | Key references in a token are refused unless the profile opts in; jwz fetches nothing; a `JwkSet` only compares `kid` | A resolver that looks `kid` up in a database or directory escapes it; one that fetches holds the URL to an allowlist and sends no cookies |
| 3.11 | Explicit typing | `Policy::typ` requires the `typ`, compared as a media type (`application/` optional, case ignored); `HeaderParams::typ` sets it | Name a new kind `example+jwt`; set `HeaderParams::typ` when you sign, since signing does not take it from the policy; in a Nested JWT the inner JWS carries it |
| 3.12 | Mutually exclusive rules for different kinds of JWT | A profile per kind, told apart by `typ`, `issuer`, `audience`, `required` claims or keys | Write the profiles so that each refuses the others' tokens |

### The revision: draft-ietf-oauth-rfc8725bis-10

The IETF is revising RFC 8725; jwz follows draft-ietf-oauth-rfc8725bis-10 and is checked
again when a later revision appears. What it adds or tightens, beyond the rows above, is
proven by the tests named `draft_ietf_oauth_rfc8725bis_10_3_<n>_…`. The traceability table
reads RFC numbers only, so this table traces them.

| § | Requirement | jwz | Yours |
| --- | --- | --- | --- |
| 3.1, 2.11 | Allowlists, not blocklists; `alg` consistent with the key `kid` found; the algorithms permitted per issuer | The lists are allowlists matched exactly, `none` refused in every casing; a JWK Set offers no key published for another `alg` | A profile per issuer where issuers differ in their algorithms |
| 3.2 | `none` MUST NOT be produced or consumed; fully specified names preferred | `none` never; `strict` lists `Ed25519`, and the polymorphic `EdDSA` comes only with the `EDDSA` bundle | Add `EDDSA` only for peers that still need it |
| 3.3 | Unsecured, signed, encrypted and nested JWTs told apart | `Jws` and `Jwe` are separate types and parsers, neither parses the other, and an unsecured JWT is never parsed | Tell a nested JWT by its `cty` |
| 3.9 | `aud` also when an issuer may serve more recipients later | As RFC 8725 §3.9 | Set `audience` |
| 3.10 | `kid` validated before a lookup (now a MUST); no request to a loopback or local address without an allowlist | jwz fetches nothing | A fetching resolver refuses names that resolve to loopback or local addresses |
| 3.11 | A `typ` without `/` is `application/` + `typ`; `JWT` is no explicit type | Compared so; a profile with another `typ` refuses `JWT` | `Policy::typ` requires a `typ`; for a kind of token that never carried one, check yourself that a `typ`, if present, is the expected one (`Jws::header`) |
| 3.13, 2.10 | An upper limit on PBES2 iterations | No PBES2, so no `p2c` is ever run | – |
| 3.14, 2.13 | A compact token is base64url and dots only | Every part is decoded as strict base64url; claims come only from a verified payload | – |
| 3.15, 2.12 | An upper limit on decompression | Nothing is decompressed: `zip` is refused | – |
