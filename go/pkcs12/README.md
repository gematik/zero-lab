# pkcs12

PKCS#12 (RFC 7292) encoding and decoding for Go: the `.p12` and `.pfx` containers of X.509
certificates and their private keys. Byte-oriented, no platform dependencies, builds for
WebAssembly.

| Package | Reads | Writes |
|---|---|---|
| [`pkcs12`](.) | DER; PBES2 (PBKDF2, AES-CBC), pbeWithSHAAnd3-KeyTripleDES-CBC; MAC with SHA-1 to SHA-512 | DER; PBES2 AES-CBC, HMAC-SHA-256/384/512 MAC |
| [`pkcs12/legacy`](legacy) | additionally BER, RC2-40/128, two-key Triple DES, DES-EDE3-CBC in PBES2 | — |
| [`pkcs12/legacy/ber`](legacy/ber) | BER to DER conversion | |
| [`pkcs12/legacy/rc2`](legacy/rc2) | RC2 (RFC 2268) | |

Use `legacy.Decode` when files come from Java keystores, Windows, `openssl pkcs12 -legacy` or the
card vendors of the telematics infrastructure; it returns the same `Bags` and errors as
`pkcs12.Decode`.

## Installation

```bash
go get github.com/gematik/zero-lab/go/pkcs12
```

## Usage

```go
bags, err := pkcs12.Decode(data, []byte("password")) // or legacy.Decode
if err != nil {
    return err
}
for _, pair := range bags.FindMatchingPairs() {
    cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
    key, _ := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
    // ...
}
```

```go
data, err := pkcs12.Encode(&pkcs12.Bags{
    Certificates: []pkcs12.CertificateBag{{Raw: certDER, LocalKeyID: id}},
    PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER, LocalKeyID: id}},
}, []byte("password"))
```

`Encode` writes what OpenSSL 3 writes by default: PBES2 with AES-256-CBC and PBKDF2-HMAC-SHA-256 for
keys and certificates, 2048 iterations, an HMAC-SHA-256 MAC. `EncodeWithOptions` changes cipher,
MAC digest, iterations and passwords. `Parse`, `ExtractBags`, `VerifyMAC` and the `Parse*` and
`Decrypt*` functions give access to every layer; see the package documentation.

## Security posture

- The MAC is verified before anything inside the authSafe is parsed. A file without MAC is
  accepted; `Parse` followed by a check of `pfx.MacData` rejects it.
- Unknown algorithms fail (`ErrUnsupportedAlgorithm`), including the public-key modes, PBMAC1,
  RC4 and unknown PBKDF2 PRFs. Iteration counts above 10,000,000 fail (`ErrLimitExceeded`).
- Legacy algorithms are read-only and live in `pkcs12/legacy`.
- Errors are sentinel values for `errors.Is`: `ErrInvalidPFX`, `ErrParse`, `ErrAuthentication`
  (wrong password or altered file), `ErrDecryption`, `ErrUnsupportedAlgorithm`,
  `ErrLimitExceeded`.

## Specification and tests

The rules this module implements are written down language-neutrally in
[`spec/pkcs12`](../../spec/pkcs12), together with a conformance corpus that OpenSSL generates per
run and an interoperability matrix against Rust, OpenSSL, pyca/cryptography and the JDK. The
tests run that corpus (`openssl` on the `PATH`; without it those tests skip), the RFC 2268 and
RFC 6070/7914 test vectors and two vendor files.

```bash
go test -race ./...
just golangci pkcs12   # from go/: golangci-lint with the workspace configuration
```
