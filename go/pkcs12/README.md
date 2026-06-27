# PKCS#12 Parser and Encoder

A Go implementation of PKCS#12 (RFC 7292) for encoding and decoding .p12/.pfx files containing X.509
certificates and private keys.

## Features

- RFC 7292 compliant parsing and encoding
- Modern cryptography: PBES2/PBKDF2 with AES-128/192/256-CBC
- Legacy read support: 3DES-CBC for compatibility
- MAC verification with SHA-256/384/512
- Zero-copy parsing via `golang.org/x/crypto/cryptobyte`
- Byte-oriented API: works with `[]byte`, no file I/O
- WebAssembly compatible: no syscalls or platform dependencies
- No MD5, RC4, single DES, or weak RC2

## Installation

```bash
go get github.com/gematik/zero-lab/go/pkcs12
```

## Quick Start

### Read PKCS#12 data

```go
import "github.com/gematik/zero-lab/go/pkcs12"

// Read data (from file, HTTP, embedded, etc.)
data, _ := os.ReadFile("keystore.p12")

// Decode in one step
bags, err := pkcs12.Decode(data, []byte("password"))
if err != nil {
    log.Fatal(err)
}

for _, certBag := range bags.Certificates {
    cert, _ := x509.ParseCertificate(certBag.Raw)
    fmt.Println("Certificate:", cert.Subject)
}

for _, keyBag := range bags.PrivateKeys {
    key, _ := x509.ParsePKCS8PrivateKey(keyBag.Raw)
    fmt.Printf("Key: %T\n", key)
}
```

### Create PKCS#12 data

```go
bags := &pkcs12.Bags{
    Certificates: []pkcs12.CertificateBag{{
        Raw:        certDER,
        LocalKeyID: []byte{1, 2, 3, 4},
    }},
    PrivateKeys: []pkcs12.PrivateKeyBag{{
        Raw:        keyDER,
        LocalKeyID: []byte{1, 2, 3, 4},
    }},
}

// Encode (AES-256-CBC, HMAC-SHA256, 2048 iterations)
p12Data, err := pkcs12.Encode(bags, []byte("password"))

os.WriteFile("keystore.p12", p12Data, 0600)
```

### Custom security options

```go
opts := pkcs12.DefaultEncodeOptions()
opts.Iterations = 10000
opts.MacAlgorithm = pkcs12.OIDSHA512

p12Data, _ := pkcs12.EncodeWithOptions(bags, password, opts)
```

## API overview

High-level (recommended):

```go
Decode(data, password) (*Bags, error)           // Parse and extract
Encode(bags, password) ([]byte, error)          // Create PKCS#12
EncodeWithOptions(bags, password, opts) ([]byte, error)
```

Mid-level:

```go
Parse(data) (*PFX, error)                        // Parse structure
ExtractBags(pfx, password) (*Bags, error)        // Extract bags
```

Low-level:

```go
ParseAuthenticatedSafe(data) (*AuthenticatedSafe, error)
ParseSafeContents(data) (*SafeContents, error)
DecryptShroudedKeyBag(bag, password) ([]byte, error)
VerifyMAC(pfx, password) error
```

## Types

High-level:

- `Bags` — collection of certificates and keys
- `CertificateBag` — certificate with metadata (FriendlyName, LocalKeyID)
- `PrivateKeyBag` — private key with metadata
- `CertKeyPair` — matched certificate and key

Low-level:

- `PFX` — top-level PKCS#12 structure
- `ContentInfo` — container for encrypted or unencrypted data
- `SafeContents` — collection of bags
- `SafeBag` — individual certificate or key
- `MacData` — MAC for integrity verification

## WebAssembly

The library has no file I/O or platform-specific dependencies, so it runs in WebAssembly targets (browsers,
Node.js, edge runtimes). Callers provide the bytes:

```go
//go:build wasm

package main

import "github.com/gematik/zero-lab/go/pkcs12"

//export decodePKCS12
func decodePKCS12(data []byte, password []byte) []byte {
    bags, _ := pkcs12.Decode(data, password)
    return serializeBags(bags)
}
```

## Security

Default encoding:

- AES-256-CBC for key encryption
- PBKDF2 with 2048 iterations
- HMAC-SHA256 for the MAC

Supported algorithms:

- PBES2 with AES-128/192/256-CBC
- PBKDF2 with SHA-256/384/512
- 3DES-CBC (read only, legacy)

Unsupported by design: MD5-based algorithms, RC4, single DES, weak RC2 variants.

## Structure

```
PFX
├── Version (3)
├── AuthSafe (ContentInfo)
│   └── AuthenticatedSafe
│       └── [ContentInfo...]
│           ├── Data (unencrypted SafeContents)
│           └── EncryptedData (encrypted SafeContents)
│               └── SafeContents
│                   └── [SafeBag...]
│                       ├── CertBag
│                       ├── PKCS8ShroudedKeyBag (encrypted)
│                       ├── KeyBag (unencrypted)
│                       └── Attributes
└── MacData (optional)
```

## Examples

Find matching certificate/key pairs:

```go
pairs := bags.FindMatchingPairs()
for _, pair := range pairs {
    cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
    key, _ := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
    // Use the matched cert and key together
}
```

Low-level parsing:

```go
pfx, _ := pkcs12.Parse(data)

if err := pkcs12.VerifyMAC(pfx, password); err != nil {
    log.Fatal("MAC verification failed")
}

authSafe, _ := pkcs12.ParseAuthenticatedSafe(pfx.RawAuthSafe)
for _, ci := range authSafe.ContentInfos {
    if ci.ContentType.Equal(pkcs12.OIDData) {
        safeContents, _ := pkcs12.ParseSafeContents(ci.Content)
        // Process bags...
    }
}
```

## Design

The library follows Go standard-library conventions:

- Byte-oriented, like `encoding/json` and `crypto/x509` — works with `[]byte`.
- No file I/O — callers use `os.ReadFile`/`os.WriteFile`, which composes better and keeps the package
  WebAssembly-friendly.

## Testing

```bash
go test ./...
```

## Troubleshooting

### BER indefinite-length encoding error

An error mentioning `BER indefinite-length encoding detected (0x30 0x80)` means the file uses an older
encoding that must be converted to DER. RFC 7292 mandates DER, and this parser requires it for security and
predictability. Convert with OpenSSL 3.x (legacy algorithms enabled):

```bash
openssl pkcs12 -in file.p12 -out temp.pem -nodes -passin pass:PASSWORD -legacy
openssl pkcs12 -export -in temp.pem -out converted.p12 -passout pass:PASSWORD
rm temp.pem
```

Or use `ti pkcs12 convert <input> <output>`, which handles the conversion.

### Legacy algorithms

OpenSSL 3.0+ requires `-legacy` for old encryption algorithms (RC2, MD5-based, etc.):

```bash
openssl pkcs12 -in old.p12 -out new.p12 -legacy
```

This library reads legacy 3DES-CBC and SHA-1 MAC, but does not support MD5, RC4, single DES, or weak RC2.

## References

- [RFC 7292](https://tools.ietf.org/html/rfc7292) — PKCS #12 v1.1
- [RFC 8018](https://tools.ietf.org/html/rfc8018) — PKCS #5 v2.1

## License

See the `LICENSE` file in the repository root.
