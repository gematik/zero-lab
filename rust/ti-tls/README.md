# ti-tls

TLS server verification for clients of the gematik Telematikinfrastruktur (TI), under the two
profiles of [`spec/pki-validation`](../../spec/pki-validation/README.md):

- **`ti`**, for servers of the TI: trust only from the verified TSL and roots.json, judged by
  `ti_pki::tls::ServerCheck` (TUC_PKI_018 with Tab_PKI_273, C.FD.TLS-S/C.ZD.TLS-S, the host in
  the commonName or a `dNSName`, OCSP stapled or asked).
- **`web`**, for servers on the internet: the host system's default roots (`WebCheck::system`,
  as Go and the containers' `ca-certificates` have them), with the requirements gematik and the
  ZETA SDK add: end-entity keys ECDSA P-256/P-384 or RSA ≥ 3000, CA keys RSA ≥ 2048, no SHA-1,
  MD5 or SHA-224, serverAuth, the host in a `dNSName`, at most 398 days of validity, and a
  revocation status from stapled OCSP, the responder or the CRL, or no connection.

The profile is the endpoint's, by configuration; neither falls back to the other.

- `client_config(verifier)`: a rustls `ClientConfig` offering TLS 1.3 and 1.2, AES-GCM with
  ECDHE, and P-256/P-384 only, as `testdata/handshake.json` lists it.
- `TiVerifier` and `WebVerifier`: the profiles as rustls `ServerCertVerifier`s, over one snapshot
  of trust material each; `TiVerifier::replace` swaps the TI's for a refreshed TSL while
  connections use the verifier. An accepted verdict is reused for the same chain and host until
  its certificate, its revocation status (its `nextUpdate`, at most an hour under `ti` and a day
  under `web`) or its snapshot ends; a refusal never is. A verifier keeps at most 4096 verdicts.
- `Fetch`: the host's way to an OCSP responder or CRL host for `web`; `ti` takes ti-pki's
  `OcspChecker` over the host's transport.

Certificates and handshake signatures verify with ti-pki's algorithms (brainpool included for
`ti`); rustls-webpki builds the `web` paths. The corpus of the spec is run by
`tests/corpus.rs` here and `tests/tls_corpus.rs` in ti-pki.

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
