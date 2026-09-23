# ti-pki

X.509 certificate validation against the rules of the gematik Telematikinfrastruktur (TI)
PKI: chains built through the intermediates the TSL publishes up to gematik's root anchors,
RFC 5280 path checks, OCSP revocation, and the role-OID and certificate-policy requirements
gemSpec_OID attaches to each certificate type, packaged as named profiles for the common TI
use cases.

## Status

Skeleton. The trust configuration is implemented; the module layout, the error codes, the
certificate types and the revocation modes are declared, but there is no validation logic
yet. Do not use this crate to make trust decisions.

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

## Features

| Feature | Effect |
| --- | --- |
| `dangerous-nonprod` | Non-production presets, anchors and roots |
| `test-util` | `TrustConfig::for_lab_ca`, `FixedClock` and `MockTransport` for tests in downstream crates |
| `load` | Loaders, cache, reloader; no HTTP client or executor; builds for wasm32 |
| `os` | `FileTransport`, `SystemClock`, bundle files |
| `reqwest` | `ti_pki::reqwest::ReqwestTransport` over a caller-provided client (native and wasm32) |
| `tokio` | `ti_pki::tokio`: background reloader, SIGHUP, admin trigger |

The roots walk and TSL signature check are not ported yet; until they are, the reloader
panics when it verifies changed material.

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
