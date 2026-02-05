# PKCS#12 Parser and Encoder

A Go implementation of PKCS#12 (RFC 7292) for encoding and decoding .p12/.pfx files containing X.509 certificates and private keys.

## Features

- ✅ RFC 7292 compliant parsing and encoding
- ✅ Modern cryptography: PBES2/PBKDF2 with AES-128/192/256-CBC  
- ✅ Legacy support: 3DES-CBC for compatibility
- ✅ MAC verification with SHA-256/384/512
- ✅ Zero-copy parsing using cryptobytes
- ✅ **Byte-oriented API** - works with `[]byte`, no file I/O
- ✅ **WASM compatible** - no syscalls or platform dependencies
- ✅ Security-focused: No MD5, RC4, or weak algorithms

## Installation

```bash
go get github.com/gematik/zero-lab/go/pkcs12
```

## Quick Start

### Read PKCS#12 Data

```go
import "github.com/gematik/zero-lab/go/pkcs12"

// Read data (from file, HTTP, embedded, etc.)
data, _ := os.ReadFile("keystore.p12")

// Decode in one step
bags, err := pkcs12.Decode(data, []byte("password"))
if err != nil {
    log.Fatal(err)
}

// Use certificates
for _, certBag := range bags.Certificates {
    cert, _ := x509.ParseCertificate(certBag.Raw)
    fmt.Println("Certificate:", cert.Subject)
}

// Use private keys
for _, keyBag := range bags.PrivateKeys {
    key, _ := x509.ParsePKCS8PrivateKey(keyBag.Raw)
    fmt.Printf("Key: %T\n", key)
}
```

### Create PKCS#12 Data

```go
// Create bags
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

// Encode (uses AES-256, SHA-256, 2048 iterations)
p12Data, err := pkcs12.Encode(bags, []byte("password"))

// Write to file
os.WriteFile("keystore.p12", p12Data, 0600)
```

### Custom Security Options

```go
opts := pkcs12.DefaultEncodeOptions()
opts.Iterations = 10000                    // More iterations
opts.MacAlgorithm = pkcs12.OIDSHA512       // SHA-512 MAC

p12Data, _ := pkcs12.EncodeWithOptions(bags, password, opts)
```

## API Overview

### High-Level (Recommended)

```go
Decode(data, password) (*Bags, error)           // Parse and extract
Encode(bags, password) ([]byte, error)          // Create PKCS#12
EncodeWithOptions(bags, password, opts) ([]byte, error)
```

### Mid-Level

```go
Parse(data) (*PFX, error)                       // Parse structure
ExtractBags(pfx, password) (*Bags, error)       // Extract bags
```

### Low-Level

```go
ParseAuthenticatedSafe(data) (*AuthenticatedSafe, error)
ParseSafeContents(data) (*SafeContents, error)
DecryptShroudedKeyBag(bag, password) ([]byte, error)
VerifyMAC(pfx, password) error
```

## Types

**High-level:**
- `Bags` - Collection of certificates and keys
- `CertificateBag` - Certificate with metadata (FriendlyName, LocalKeyID)
- `PrivateKeyBag` - Private key with metadata
- `CertKeyPair` - Matched certificate and key

**Low-level:**
- `PFX` - Top-level PKCS#12 structure
- `ContentInfo` - Container for encrypted or unencrypted data
- `SafeContents` - Collection of bags
- `SafeBag` - Individual certificate or key
- `MacData` - MAC for integrity verification

## WASM Usage

This library works in WebAssembly environments:

```go
//go:build wasm

package main

import "github.com/gematik/zero-lab/go/pkcs12"

//export decodePKCS12
func decodePKCS12(data []byte, password []byte) []byte {
    bags, _ := pkcs12.Decode(data, password)
    // Process bags and return result
    return serializeBags(bags)
}
```

No file I/O means it works everywhere: browsers, Node.js, edge workers, etc.

## Security

**Default encoding uses:**
- AES-256-CBC for key encryption
- PBKDF2 with 2048 iterations
- HMAC-SHA256 for MAC

**Supported algorithms:**
- PBES2 with AES-128/192/256-CBC
- PBKDF2 with SHA-256/384/512
- 3DES-CBC (legacy)

**Intentionally unsupported:**
- MD5-based algorithms
- RC4
- Single DES
- Weak RC2 variants

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

### Find Matching Pairs

```go
pairs := bags.FindMatchingPairs()
for _, pair := range pairs {
    cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
    key, _ := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
    // Use matched cert and key together
}
```

### Low-Level Parsing

```go
pfx, _ := pkcs12.Parse(data)

// Verify MAC
if err := pkcs12.VerifyMAC(pfx, password); err != nil {
    log.Fatal("MAC verification failed")
}

// Parse authenticated safe
authSafe, _ := pkcs12.ParseAuthenticatedSafe(pfx.RawAuthSafe)

// Process each ContentInfo
for _, ci := range authSafe.ContentInfos {
    if ci.ContentType.Equal(pkcs12.OIDData) {
        safeContents, _ := pkcs12.ParseSafeContents(ci.Content)
        // Process bags...
    }
}
```

## Testing

```bash
go test -v
```

180 tests, 80.4% coverage.

## Design Philosophy

This library follows Go standard library patterns:

- **Byte-oriented**: Like `encoding/json`, `crypto/x509` - works with `[]byte`
- **No file I/O**: Users call `os.ReadFile`/`os.WriteFile` - more composable
- **WASM-friendly**: No platform-specific dependencies
- **Interface-compatible**: Works with `io.Reader`/`Writer` via `io.ReadAll`

## References

- [RFC 7292](https://tools.ietf.org/html/rfc7292) - PKCS #12 v1.1
- [RFC 8018](https://tools.ietf.org/html/rfc8018) - PKCS #5 v2.1

## License

See LICENSE file in repository root.

## Troubleshooting

### BER Indefinite-Length Encoding Error

If you see an error about "BER indefinite-length encoding detected (0x30 0x80)", your PKCS#12 file uses an older encoding format that must be converted to DER.

**Solution for OpenSSL 3.x (with legacy algorithms):**

```bash
openssl pkcs12 -in file.p12 -out temp.pem -nodes -passin pass:PASSWORD -legacy
openssl pkcs12 -export -in temp.pem -out converted.p12 -passout pass:PASSWORD
rm temp.pem
```

**Why?**
- BER (Basic Encoding Rules) allows indefinite-length encoding
- DER (Distinguished Encoding Rules) requires definite lengths
- RFC 7292 mandates DER for PKCS#12
- This parser requires strict DER compliance for security and predictability

### Legacy Algorithms

OpenSSL 3.0+ requires the `-legacy` flag for old encryption algorithms (RC2, MD5-based, etc.):

```bash
openssl pkcs12 -in old.p12 -out new.p12 -legacy
```

Our library supports:
- ✅ Modern: PBES2 with AES-128/192/256-CBC, PBKDF2, SHA-256/384/512
- ✅ Legacy (read-only): 3DES-CBC, SHA-1 MAC
- ❌ Not supported: MD5, RC4, single DES, weak RC2

