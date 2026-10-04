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
| `verify_tsl(xml, env, now, roots_json?, grace_seconds)` | the TSL view, [`schemas/tsl-view.json`](schemas/tsl-view.json) |
| `describe_certificate(der_or_pem, now)` | [`schemas/certificates.json`](schemas/certificates.json), as `ti pki inspect` |

`env` is `prod`, `ref`, `test` or `dev`; `now` is RFC 3339. A thrown `Error` means a
wrong call (unknown environment, bad time, grace period over 30 days, no certificate);
every verification verdict, including an invalid list, is inside the JSON.

The TSL view verifies the list's signature and signer under the TSL signer CA of the
environment's tier (`spec/tsl-xmldsig`), matches its CAs against the roots walked from the
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
