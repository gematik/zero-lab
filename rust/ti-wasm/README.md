# ti-wasm

gematik Telematikinfrastruktur (TI) TSL verification and certificate reports as
WebAssembly, for JavaScript on a server (Node) and in a browser. Every export is a pure
function: the caller passes the TSL, roots.json and the instant, and gets JSON back.
Downloads, caching and the clock stay in JavaScript (the TI download hosts send no CORS
headers, the OCSP responders speak plain HTTP).

| Export | Returns |
| --- | --- |
| `version()` | `{ti_wasm, schema}` |
| `trust_urls(env)` | `{environment, tsl_url, roots_url}` |
| `verify_tsl(xml, sig, ocsp?, env, now, roots_json?, grace_seconds)` | the TSL view, [`schemas/tsl-view.json`](schemas/tsl-view.json): the list verified by its detached `.sig`, the status from `.ocsp` if given (`spec/tsl-detached`) |
| `describe_certificate(der_or_pem, now)` | [`schemas/certificates.json`](schemas/certificates.json), as `ti pki inspect` |
| `new TrustContext(xml, sig, env, now, roots_json?, grace_seconds)` | verifies the TSL and roots once; `.tsl()` their state |
| `TrustContext.check(der_or_pem, now)` | [`schemas/check.json`](schemas/check.json): a certificate as `ti pki verify --profile auto --offline` judges it, with its trust tree |

`env` is `prod`, `ref`, `test` or `dev`; `now` is RFC 3339. A thrown `Error` means a
wrong call (unknown environment, bad time, grace period over 30 days, no certificate);
every verification verdict, including an invalid list, is inside the JSON.

`TrustContext` is meant for the browser: the TSL and roots are verified once (about 100 ms),
then each certificate in a few milliseconds, and nothing leaves the page. Revocation is not
checked (OCSP needs a network); the report says `revocation: "not_checked"`.

The TSL view verifies the list's detached signature and signer under the TSL signer CA of the
environment's tier (`spec/tsl-detached`), matches its CAs against the roots walked from the
environment's anchor, and lists every service with the chain of its certificate. A
supplied roots.json is used only if it walks from the anchor, so it cannot add a root.
The module embeds the TEST-ONLY anchors of the test environments (`dangerous-nonprod`);
a production request still only accepts production trust material.

## Build

```console
just wasm-build    # target/ti-wasm/pkg
just wasm-smoke    # Node on the real TSLs, cross-checked with ti pki tsl verify
just wasm-size
just wasm-vendor   # into ../../gemiverse/vendor/ti-wasm
```

Needs `wasm-bindgen-cli` at the version pinned in `Cargo.toml` (`just tools`) and binaryen's
`wasm-opt` for an optimized build.

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
