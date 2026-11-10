# ti-pkcs12

PKCS#12 (RFC 7292) decoding for the identities of the gematik Telematikinfrastruktur
(TI): the `.p12` files of SMC-B, HBA and component test cards and of soft keys. It and
`go/pkcs12` are held to the same specification, `spec/pkcs12`.

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
  constructed strings. `der`'s BER mode decodes them. The MAC is checked over the auth-safe octets
  as received, before anything inside is parsed.
- **Integrity:** the password mode with HMAC-SHA-1, -224, -256, -384 or -512 and the
  PKCS#12 KDF (RFC 7292 Appendix B).
- **Encryption:** PBES2 (PBKDF2, AES-128/192/256-CBC). With the
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

With the `encode` feature, `encode` writes a file as OpenSSL 3 does by default:
- certificates in a safe encrypted with PBES2 AES-256-CBC (PBKDF2-HMAC-SHA-256, 2048
  iterations);
- keys in shrouded key bags with the same encryption;
- an HMAC-SHA-256 MAC;
- attributes kept.

Such files need no `-legacy` in OpenSSL 3, and `pkcs12.Decode` of `go/pkcs12` reads them.
The caller supplies the randomness for salts and IVs, so the crate
has no OS dependency.

The crate builds for `wasm32-unknown-unknown`.

## Tests

The fixtures are those of `go/pkcs12`, copied unchanged and pinned by SHA-256:
- OpenSSL-generated files for AES-128/256, 3DES, no MAC, the empty password, a chain
  and an EC key;
- two BER vendor files (`legacy/`).

Every one decodes to the certificates, keys and pairs the Go decoder reports
(`tests/fixtures/go-baseline.json`). One exception for the BER files: that baseline was
written through an OpenSSL re-export, which rewrites attributes and re-encodes keys. There, the
attributes and private scalars are pinned to what `openssl pkcs12 -info` shows in the
originals.

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
