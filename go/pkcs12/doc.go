// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Package pkcs12 encodes and decodes PKCS#12 files (RFC 7292), the .p12 and
// .pfx containers of X.509 certificates and their private keys.
//
// The package works on byte slices, has no platform dependencies and builds
// for WebAssembly. Certificates come back as DER (x509.ParseCertificate),
// keys as PKCS#8 DER (x509.ParsePKCS8PrivateKey).
//
// # Decoding
//
// Decode verifies the MAC, decrypts every safe and returns the bags:
//
//	bags, err := pkcs12.Decode(data, password)
//	for _, pair := range bags.FindMatchingPairs() {
//		cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
//		key, _ := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
//	}
//
// Parse and ExtractBags split this in two steps, e.g. to insist on a MAC
// (pfx.MacData != nil) before decrypting. ParseAuthenticatedSafe,
// ParseSafeContents, DecryptEncryptedData, DecryptShroudedKeyBag and
// VerifyMAC give access to every layer.
//
// This package reads DER. Files in BER encoding, or encrypted with RC2,
// two-key Triple DES or DES-EDE3 in PBES2, as Java keystores, Windows,
// OpenSSL -legacy and the card vendors of the telematics infrastructure write
// them, are read by package legacy, whose Decode returns the same Bags.
//
// # Encoding
//
// Encode writes the format of OpenSSL 3's default export: PBES2 with
// AES-256-CBC and PBKDF2-HMAC-SHA-256 for keys and the certificate safe,
// 2048 iterations, an HMAC-SHA-256 MAC, random salts and IVs, DER.
// EncodeWithOptions selects AES-128/192, SHA-384/512, more iterations,
// separate passwords, unencrypted certificates or no MAC.
//
// # Security posture
//
// Accepted when reading:
//   - integrity: HMAC with SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 and the
//     PKCS#12 key derivation (RFC 7292 appendix B); a file without MAC is
//     accepted and has pfx.MacData == nil;
//   - privacy: PBES2 with PBKDF2 (HMAC-SHA-1 to -SHA-512) and AES-CBC, and
//     pbeWithSHAAnd3-KeyTripleDES-CBC.
//
// Rejected: the public-key integrity and privacy modes, PBMAC1 (RFC 9579),
// RC4, single DES, unknown PRFs and ciphers (ErrUnsupportedAlgorithm), and
// iteration counts above 10,000,000 (ErrLimitExceeded). The MAC is checked
// before anything inside the authSafe is parsed. Legacy algorithms are never
// written.
//
// # Errors
//
// Test errors with errors.Is: ErrInvalidPFX and ErrParse for structure,
// ErrAuthentication for a MAC mismatch (wrong password or altered file),
// ErrDecryption for ciphertext that does not decrypt (wrong password in a
// file without MAC), ErrUnsupportedAlgorithm and ErrLimitExceeded.
//
// The language-neutral specification and conformance corpus this package is
// tested against are in spec/pkcs12 of the repository.
package pkcs12
