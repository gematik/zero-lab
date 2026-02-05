// Package pkcs12 implements PKCS#12 (RFC 7292) encoding and decoding.
//
// PKCS#12 is a binary format for storing and transporting X.509 certificates
// and their associated private keys, typically in .p12 or .pfx files.
//
// # Features
//
// This package provides:
//   - Full RFC 7292 compliant parsing and encoding
//   - Modern cryptography: PBES2/PBKDF2 with AES-128/192/256-CBC
//   - Legacy support: 3DES-CBC for compatibility
//   - MAC verification with SHA-256/384/512
//   - Zero-copy parsing using cryptobytes
//   - Byte-oriented API (no file I/O dependencies)
//
// # Quick Start
//
// Read PKCS#12 data:
//
//data, _ := os.ReadFile("keystore.p12")
//bags, err := pkcs12.Decode(data, []byte("password"))
//if err != nil {
//log.Fatal(err)
//}
//
//for _, certBag := range bags.Certificates {
//cert, _ := x509.ParseCertificate(certBag.Raw)
//fmt.Println("Certificate:", cert.Subject)
//}
//
// Create PKCS#12 data:
//
//bags := &pkcs12.Bags{
//Certificates: []pkcs12.CertificateBag{{
//Raw:        certDER,
//LocalKeyID: []byte{1, 2, 3, 4},
//}},
//PrivateKeys: []pkcs12.PrivateKeyBag{{
//Raw:        keyDER,
//LocalKeyID: []byte{1, 2, 3, 4},
//}},
//}
//
//p12Data, err := pkcs12.Encode(bags, []byte("password"))
//os.WriteFile("keystore.p12", p12Data, 0600)
//
// # API Levels
//
// The package provides three levels of API:
//
// High-Level (Recommended):
//
//Decode(data, password) - Parse and extract in one step
//Encode(bags, password) - Create PKCS#12 with secure defaults
//EncodeWithOptions(bags, password, opts) - Custom options
//
// Mid-Level:
//
//Parse(data) + ExtractBags(pfx, password) - Two-step decode
//Individual bag extraction functions
//
// Low-Level:
//
//ParseAuthenticatedSafe(data) - Parse structure
//ParseSafeContents(data) - Parse bags
//DecryptShroudedKeyBag(bag, password) - Decrypt keys
//VerifyMAC(pfx, password) - Verify integrity
//
// # WASM Compatibility
//
// This package is designed to work in WebAssembly:
//   - No file I/O - works with []byte
//   - No platform-specific syscalls
//   - Pure Go cryptography
//
// Example WASM usage:
//
////export decodePKCS12
//func decodePKCS12(data []byte, password []byte) []byte {
//bags, _ := pkcs12.Decode(data, password)
//// Return serialized bags
//}
//
// # Security
//
// Default encoding uses modern cryptography:
//
//Encryption:  AES-256-CBC with PBKDF2
//KDF:         PBKDF2 with 2048 iterations
//MAC:         HMAC-SHA256
//
// Supported algorithms:
//   - PBES2 with AES-128/192/256-CBC
//   - PBKDF2 with SHA-256/384/512
//   - 3DES-CBC (legacy compatibility)
//
// Intentionally unsupported (insecure):
//   - MD5-based algorithms
//   - RC4
//   - Single DES
//   - Weak RC2 variants
//
// # Structure
//
// PKCS#12 follows this hierarchy:
//
//PFX
//├── Version (3)
//├── AuthSafe (ContentInfo)
//│   └── AuthenticatedSafe
//│       └── [ContentInfo...]
//│           ├── Data (unencrypted SafeContents)
//│           └── EncryptedData (encrypted SafeContents)
//│               └── SafeContents
//│                   └── [SafeBag...]
//│                       ├── CertBag
//│                       ├── PKCS8ShroudedKeyBag (encrypted)
//│                       ├── KeyBag (unencrypted)
//│                       └── Attributes (FriendlyName, LocalKeyID)
//└── MacData (optional integrity check)
//
// # Types
//
// Core structures (low-level):
//
//PFX - Top-level PKCS#12 structure
//ContentInfo - Container for encrypted or unencrypted data
//SafeContents - Collection of SafeBags
//SafeBag - Individual item (certificate or key)
//MacData - MAC for integrity verification
//
// High-level types:
//
//Bags - Collection of certificates and keys
//CertificateBag - Certificate with metadata
//PrivateKeyBag - Private key with metadata
//CertKeyPair - Matched certificate and key
//
// # Examples
//
// Custom encoding options:
//
//opts := pkcs12.DefaultEncodeOptions()
//opts.Iterations = 10000                    // More iterations
//opts.MacAlgorithm = pkcs12.OIDSHA512       // SHA-512 for MAC
//
//p12Data, _ := pkcs12.EncodeWithOptions(bags, password, opts)
//
// Find matching certificates and keys:
//
//pairs := bags.FindMatchingPairs()
//for _, pair := range pairs {
//cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
//key, _ := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
//// Use matched cert and key
//}
//
// Low-level parsing:
//
//pfx, _ := pkcs12.Parse(data)
//
//// Verify MAC
//if err := pkcs12.VerifyMAC(pfx, password); err != nil {
//log.Fatal("MAC verification failed:", err)
//}
//
//// Parse authenticated safe
//authSafe, _ := pkcs12.ParseAuthenticatedSafe(pfx.RawAuthSafe)
//
//// Process each ContentInfo
//for _, ci := range authSafe.ContentInfos {
//if ci.ContentType.Equal(pkcs12.OIDData) {
//// Unencrypted data
//safeContents, _ := pkcs12.ParseSafeContents(ci.Content)
//// Process bags...
//}
//}
//
// # References
//
// RFC 7292: PKCS #12: Personal Information Exchange Syntax v1.1
// https://tools.ietf.org/html/rfc7292
//
// RFC 8018: PKCS #5: Password-Based Cryptography Specification Version 2.1
// https://tools.ietf.org/html/rfc8018
package pkcs12
