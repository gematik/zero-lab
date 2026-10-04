# ti-pki

X.509 certificate validation against the rules of the gematik Telematikinfrastruktur (TI)
PKI: chains built through the intermediates the TSL publishes up to gematik's root anchors,
RFC 5280 path checks, OCSP revocation, and the role-OID and certificate-policy requirements
gemSpec_OID attaches to each certificate type, packaged as named profiles for the common TI
use cases.

## Status

Implemented: roots.json verified from the embedded anchor (the A_28419 cross-certificate
walk), the TSL's CAs kept only when a verified root signed them, chain building, path
validation, the gemSpec_Krypt key check, certificate types and profiles, OCSP for the end
entity and every CA below the root, and loading with cache, bundle and reload. The TSL
is verified as `spec/tsl-xmldsig` requires (signature, signer under the TSL signer CA,
signer OCSP, `NextUpdate`, sequence) but stays a source of candidate intermediates, not
of trust.

The gematik specifications it implements, in the versions it follows:
[gemSpec_PKI V2.28.0](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_PKI/gemSpec_PKI_V2.28.0.html),
[gemSpec_TSL V1.25.0](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_TSL/gemSpec_TSL_V1.25.0.html),
[gemSpec_Krypt V2.50.0](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.50.0.html),
[gemKPT_PKI_TIP V2.14.0](https://gemspec.gematik.de/downloads/gemKPT/gemKPT_PKI_TIP/gemKPT_PKI_TIP_V2.14.0.html).
The TSL signature rules derived from them are in
[`spec/tsl-xmldsig`](../../spec/tsl-xmldsig/README.md).

The reference implementation is the Go package
[`gempki`](https://github.com/gematik/zero-lab/tree/main/go/gempki); this crate ports it
module by module and keeps its error codes, certificate-type names and revocation table.

```toml
[dependencies]
ti-pki = { git = "https://github.com/gematik/zero-lab", tag = "rust/ti-pki/v0.1.0" }
```

## Configuration

Everything that differs between TI environments is a field of `TrustConfig`. Start from a
preset, override fields with struct update, and validate for the tier you run in:

```rust
use ti_pki::{Tier, TrustConfig};

let config = TrustConfig::preset_prod();
config.validate(Tier::Prod)?;
```

Presets for the non-production environments (`TrustConfig::preset(Env::Test)` and so on)
carry TEST-ONLY anchors and exist only with the `dangerous-nonprod` feature; production
builds leave it off.

## Loading and hot reload

With the `load` feature, `ti_pki::load` loads roots.json and the TSL through pluggable,
untrusted loaders, verifies them, and swaps them into a shared trust store. A production
wiring with a cache, an offline fallback and a background reloader:

```rust
use std::sync::Arc;
use ti_pki::load::{
    Bundle, CachePolicy, CachingLoader, FallbackLoader, HttpLoader, ReloadOutcome,
    ReloadPolicy, Reloader, StaticLoader, SystemClock,
};
use ti_pki::reqwest::ReqwestTransport;
use ti_pki::{Tier, TrustConfig};

let cfg = TrustConfig::preset_prod();
let transport = ReqwestTransport::new(client); // proxy, timeouts, TLS set by the caller
let online = CachingLoader::new(
    HttpLoader::new(&cfg, transport, SystemClock),
    my_kv, // any CacheStore
    SystemClock,
    CachePolicy::default(),
);
let bundle = StaticLoader::from_bundle(Bundle::read("/etc/ti-pki/bundle.cbor")?, &cfg)?;
let loader = FallbackLoader::new(online, bundle);
let reloader = Arc::new(Reloader::new(cfg, Tier::Prod, loader, SystemClock, ReloadPolicy::default())?);
if let ReloadOutcome::Expired { error } = reloader.tick().await {
    return Err(error.into()); // fail startup
}
let task = ti_pki::tokio::spawn_reloader(Arc::clone(&reloader))?;
let store = reloader.handle().snapshot()?; // per request
```

Air-gapped, never touching the network: serve a pre-populated store and fall back to
the bundle.

```rust
let bundle = StaticLoader::from_bundle(Bundle::read("/etc/ti-pki/bundle.cbor")?, &cfg)?;
let offline = CachingLoader::new(
    bundle.clone(),
    my_kv,
    SystemClock,
    CachePolicy { offline: true, ..CachePolicy::default() },
);
let loader = FallbackLoader::new(offline, bundle);
```

## Signature algorithms

Signatures are verified through `rustls_pki_types::SignatureVerificationAlgorithm`
implementations, chosen by key and signature algorithm. `TrustConfig::algorithms`
defaults to `ti_pki::algorithms::DEFAULT`: ECDSA on P-256, P-384, and, with the default
features, ECDSA on brainpoolP256r1 and brainpoolP384r1 (`brainpool`) and RSA PKCS#1 v1.5
and PSS (`rsa`). Further implementations of
the trait (a FIPS-validated set, post-quantum algorithms) can be added to the set:

```rust
let config = TrustConfig {
    algorithms: [ti_pki::algorithms::DEFAULT, my_extra_algorithms].concat().into(),
    ..TrustConfig::preset_prod()
};
```

## Features

| Feature | Effect |
| --- | --- |
| `dangerous-nonprod` | Non-production presets, anchors and roots |
| `test-util` | `TrustConfig::for_lab_ca`, `FixedClock` and `MockTransport` for tests in downstream crates |
| `brainpool` (default) | ECDSA on brainpoolP256r1 / brainpoolP384r1 in the default algorithm set; the TI's anchors need it |
| `rsa` (default) | RSA PKCS#1 v1.5 and PSS in the default algorithm set; the historical RSA roots GEM.RCA2/6/9 need it for the roots walk |
| `load` | Loaders, cache, reloader; no HTTP client or executor; builds for wasm32 |
| `os` | `FileTransport`, `SystemClock`, bundle files |
| `reqwest` | `ti_pki::reqwest::ReqwestTransport` over a caller-provided client (native and wasm32) |
| `tokio` | `ti_pki::tokio`: background reloader, SIGHUP, admin trigger |

## License

Copyright 2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/rust/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
