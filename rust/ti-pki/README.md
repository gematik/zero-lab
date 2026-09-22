# ti-pki

X.509 certificate validation against the rules of the gematik Telematikinfrastruktur (TI)
PKI: chains built through the intermediates the TSL publishes up to gematik's root anchors,
RFC 5280 path checks, OCSP revocation, and the role-OID and certificate-policy requirements
gemSpec_OID attaches to each certificate type, packaged as named profiles for the common TI
use cases.

## Status

Skeleton. The module layout, the environments, the error codes, the certificate types and
the revocation modes are declared; there is no validation logic yet. Do not use this crate
to make trust decisions.

The reference implementation is the Go package
[`gempki`](https://github.com/gematik/zero-lab/tree/main/go/gempki); this crate ports it
module by module and keeps its error codes, certificate-type names and revocation table.

```toml
[dependencies]
ti-pki = { git = "https://github.com/gematik/zero-lab", tag = "rust/ti-pki/v0.1.0" }
```

```rust
use ti_pki::Env;
```

## License

Copyright 2023-2026 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
