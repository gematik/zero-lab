# ti-connector-client

Client for the SOAP services of a gematik Konnektor in the Telematikinfrastruktur (TI):
the `.kon` configuration file, the service directory with version choice, and thin
facades over bindings generated from the gematik WSDLs.

```rust,no_run
use ti_connector_client::{Connector, Dotkon, Timeouts, Transport};

# async fn demo(transport: impl Transport) -> Result<(), Box<dyn std::error::Error>> {
let dotkon = Dotkon::parse(&std::fs::read("praxis.kon")?)?;
let connector = Connector::connect(&dotkon, transport, Timeouts::RECOMMENDED).await?;
for card in connector.cards().list(&[]).await? {
    println!("{} {:?} {}", card.card_type, card.iccsn, card.card_handle);
}
# Ok(()) }
```

## Services

| Facade | Service | Operations |
| --- | --- | --- |
| `cards()` | EventService 7.2 | list, get |
| `certificates()` | CertificateService 6.0 | read, read_all, expiration, verify |
| `pins()` | CardService 8.1 | status, verify, change |
| `auth()` | AuthSignatureService 7.4 | external_authenticate |

## Design

- **No HTTP code.** Requests go through the caller's `Transport`, which owns TLS
  (including the client certificate of `pkcs12` credentials), proxies, connection reuse
  and the per-request timeout. Traits have no `Send` bounds and the crate does no I/O,
  so it builds for `wasm32-unknown-unknown`.
- **Timeouts are configuration.** Every operation is `short` (lookups) or `long` (PIN
  entry, card cryptography); `Timeouts::RECOMMENDED` is 10 seconds and 5 minutes.
- **The binding picks the version.** Each service minor version has its own XML
  namespace. A call goes to the newest version the Konnektor advertises among those the
  crate has bindings for.
- **`${NAME}` in `.kon` files is safe.** Expanded only in `credentials.username`,
  `credentials.password` and `credentials.data`; anywhere else it is an error, so a
  `.kon` file from someone else cannot send environment variables to a foreign host.
  This deviates from the Go client, which expands everywhere.
- **Faults keep the gematik error trace**, read leniently: Konnektors differ in which
  trace fields they fill in.
- **Caching:** the service directory can be loaded through a `ti_cache::Cache`
  (`Connector::connect_cached`). Card data, PIN state and signatures are never cached.

## Adding an operation

1. Add it with its timeout class to `api.select.json` and run `just generate-connector`.
2. Write the facade method: build the request, `self.connector.call::<OpInput>(…)`,
   return the response or a light post-processing of it.
3. Add a fixture test with a captured response.

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
