# ti-client

The native host of the gematik Telematikinfrastruktur (TI) crates, shared by the `ti`
command-line tool and the desktop app: the I/O the product clients leave to their host.

- `connector`: ti-connector-client's transport over blocking ureq (`UreqTransport`), its TLS
  ti-tls's `konnektor` profile with the operating system's verifier for an empty trust store,
  the client certificate of `pkcs12` credentials, basic auth; the TCP and TLS probe of
  `config test` (`check_config`) and the certificates a Konnektor presents
  (`server_certificate`).
- `tls`: an agent per ti-tls profile, its rustls configuration in ureq's connector chain
  (`agent`), and the `web` profile's OCSP responders and CRL hosts over ureq (`UreqFetch`).
- `block_on`: runs a product client's future on the calling thread. Everything this crate
  plugs into a client blocks, so each future is complete at its first poll; an executor
  would only add dependencies.
- `FileCache`: the `ti_cache::CacheStore` of ti-pki's downloads and the Konnektor's service
  directory as plain files, one per key, named by the hash of the key.
- `files`: files written the way every state and cache file is: private to the user and
  never half-written.

It holds no protocol logic: a message, a check or a trust rule of a product lives in that
product's crate, and TLS trust in ti-tls. It is not for wasm32; ti-wasm uses the product
clients directly.

## License

Copyright 2026 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/rust/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
