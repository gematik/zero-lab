# ti-pkcs12

PKCS#12 (RFC 7292) decoding for the identities of the gematik Telematikinfrastruktur
(TI): the `.p12` files of SMC-B, HBA and component test cards and of soft keys. A port of
`go/pkcs12`, without its OpenSSL dependency.

```rust,no_run
# fn demo(bytes: &[u8]) -> Result<(), ti_pkcs12::Error> {
let p12 = ti_pkcs12::decode(bytes, "00")?;
for pair in p12.pairs() {
    let certificate = &p12.certificates[pair.certificate];
    let key = &p12.keys[pair.key]; // PKCS#8 DER, zeroized on drop
}
# Ok(()) }
```

```sh
cargo run -p ti-pkcs12 --example info -- identity.p12 [PASSWORD]   # password defaults to 00
```

## What it reads

- **DER and BER.** Java keystores and card vendors write indefinite lengths and
  constructed strings. `der`'s BER mode decodes them, so, unlike the Go module, no
  `openssl -legacy` conversion is needed. The MAC is checked over the auth-safe octets
  as received, before anything inside is parsed.
- **Integrity:** the password mode with HMAC-SHA-1, -224, -256, -384 or -512 and the
  PKCS#12 KDF (RFC 7292 Appendix B).
- **Encryption:** PBES2 (PBKDF2, AES-128/192/256-CBC) through `pkcs5`. With the
  `legacy` feature (default), also the PKCS#12 PBEs with 3DES and RC2-40/128 and
  DES-EDE3 in PBES2, which OpenSSL's `-legacy` and gematik's card vendors still
  produce.
- **Bags:** certificates, shrouded and plain key bags, nested safe contents;
  `friendlyName` and `localKeyId`. Certificates pair with keys by `localKeyId`.

Not supported:
- the public-key integrity and privacy modes;
- CRL and secret bags;
- PBMAC1.

Keys stay PKCS#8 DER in zeroized memory; the crate does no key cryptography.

The crate builds for `wasm32-unknown-unknown`.

## Tests

The fixtures are those of `go/pkcs12`, copied unchanged and pinned by SHA-256:
- OpenSSL-generated files for AES-128/256, 3DES, no MAC, the empty password, a chain
  and an EC key;
- two BER vendor files (`legacy/`).

Every one decodes to the certificates, keys and pairs the Go decoder reports
(`tests/fixtures/go-baseline.json`). One exception for the BER files: Go reads them
through an OpenSSL re-export, which rewrites attributes and re-encodes keys. There, the
attributes and private scalars are pinned to what `openssl pkcs12 -info` shows in the
originals.

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
