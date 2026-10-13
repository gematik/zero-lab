# pkcs12/legacy

Reads the PKCS#12 files that [`pkcs12`](..) rejects:

- **BER encoding**: indefinite lengths and constructed strings, as Java keystores, Windows and the
  card vendors of the telematics infrastructure write them;
- **RC2** with 40 or 128 bits and **two-key Triple DES** (PKCS#12 PBEs, RFC 7292 appendix C), as
  `openssl pkcs12 -legacy` writes them;
- **DES-EDE3-CBC in PBES2**.

```go
bags, err := legacy.Decode(data, password)
```

`Decode` accepts everything `pkcs12.Decode` accepts and returns the same `pkcs12.Bags` and error
values. It mirrors `pkcs12.ExtractBags` and reuses the parsers of package `pkcs12`: each nested layer
is converted from BER to DER by [`ber`](ber) first, and the legacy schemes are decrypted here, RC2
by [`rc2`](rc2). The legacy algorithms are read-only; to write a file, pass the bags to
`pkcs12.Encode`.

`ConvertWithOpenSSL` is deprecated. It no longer runs OpenSSL: it decodes with `Decode` and writes
the result with `pkcs12.Encode`. `IsBER` reports whether data starts with an indefinite-length
SEQUENCE.

The tests decode every case of the [`spec/pkcs12`](../../../spec/pkcs12) corpus and the two vendor
files in `spec/pkcs12/testdata/vendor`.
