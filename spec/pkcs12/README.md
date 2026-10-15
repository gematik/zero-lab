# PKCS#12 decoding and encoding: requirements

Language-neutral specification of how a PKCS#12 file (RFC 7292) is read and written for the
identities of the gematik telematics infrastructure: the `.p12` files of SMC-B, HBA and component
test cards, of connector client certificates and of soft keys. It is the binding basis for
`go/pkcs12` and `rust/ti-pkcs12` and for any later implementation, and a yardstick for libraries of
other ecosystems. An implementation built from this document alone and checked against the corpus
of [CONFORMANCE.md](CONFORMANCE.md) is conformant.

Each rule has one identifier `P12-nnn`. Tests and the corpus manifest cite these identifiers. The key
words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

- [Scope](#scope)
- [References](#references)
- [Profiles](#profiles)
- [Rules](#rules)
  - [A. Input and encoding](#a-input-and-encoding)
  - [B. Integrity](#b-integrity)
  - [C. Password](#c-password)
  - [D. Privacy](#d-privacy)
  - [E. Bags](#e-bags)
  - [F. Writing](#f-writing)
- [Result codes](#result-codes)
- [Algorithm](#algorithm)
- [Deviations](#deviations)
- [Security considerations](#security-considerations)

## Scope

In scope: the password integrity mode and the password privacy mode of RFC 7292, with the
algorithms the producers in the telematics infrastructure use: OpenSSL 3 and its `-legacy` mode,
Java keystores, Windows, the connector and card vendors.

Out of scope, and therefore rejected (P12-012, P12-016, P12-033, P12-035):
- the public-key integrity mode (signed authSafe) and the public-key privacy mode (enveloped safes);
- PBMAC1 (RFC 9579);
- RC4, single DES, MD2/MD5-based schemes, RC2 inside PBES2;
- CRL bags and secret bags (skipped, P12-043);
- certificate types other than X.509 (P12-040).

## References

| Short name | Document |
|---|---|
| RFC 7292 | PKCS #12: Personal Information Exchange Syntax v1.1 |
| RFC 8018 | PKCS #5: Password-Based Cryptography Specification v2.1 (PBES2, PBKDF2) |
| RFC 2315 | PKCS #7: Cryptographic Message Syntax v1.5 (ContentInfo, EncryptedData) |
| RFC 5958 | Asymmetric Key Packages (PrivateKeyInfo, EncryptedPrivateKeyInfo) |
| RFC 2268 | A Description of the RC2(r) Encryption Algorithm (test vectors §5) |
| RFC 6070, RFC 7914 §11 | PBKDF2-HMAC-SHA-1 and -SHA-256 test vectors |
| X.690 | ASN.1 encoding rules: BER (§8) and DER (§10, §11) |
| RFC 9579 | PBMAC1 for PKCS #12 (out of scope) |

RFC 7292 has no test vectors for its key derivation. The vectors of Bouncy Castle's PKCS12 tests
and of golang.org/x/crypto/pkcs12 serve instead (see `go/pkcs12/internal/pbe`).

## Profiles

A decoder implements one of two profiles:

| Profile | Adds | Implementations |
|---|---|---|
| `modern` | DER; PBES2 with AES-CBC; pbeWithSHAAnd3-KeyTripleDES-CBC; MAC with SHA-1 to SHA-512 | `go/pkcs12` (`pkcs12.Decode`) |
| `legacy` | `modern` plus BER, RC2-40/128, two-key Triple DES, DES-EDE3-CBC in PBES2 | `go/pkcs12/legacy` (`legacy.Decode`), `rust/ti-pkcs12` |

Rules marked *(legacy)* apply to the profile `legacy` only. A `modern` decoder MUST reject what only
`legacy` reads with `malformed` or `unsupported_algorithm`; it MUST NOT decode it to something else.

## Rules

### A. Input and encoding

| Rule | Requirement |
|---|---|
| P12-001 | The input MUST be a PFX: a SEQUENCE of version 3, a ContentInfo authSafe and an optional MacData. Anything else is `malformed`. |
| P12-002 | A decoder MUST accept DER. *(legacy)* It MUST also accept BER: indefinite lengths, non-minimal definite lengths and constructed strings, in every layer (PFX, authSafe octets, safes, decrypted plaintext). |
| P12-003 | Bytes after the PFX, and after any structure inside it, are `malformed`. |
| P12-004 | A decoder MUST bound nesting depth (at least 32 levels accepted) and MUST NOT allocate beyond the input size because of a length field. |
| P12-005 | *(legacy)* `encryptedContent [0] IMPLICIT OCTET STRING` MUST be accepted in constructed form (a `[0]` holding OCTET STRING segments, joined in order); generic BER conversion cannot do this because only the schema tells that this `[0]` is a string. |

### B. Integrity

| Rule | Requirement |
|---|---|
| P12-010 | If MacData is present, the decoder MUST verify the MAC before it parses anything inside the authSafe. A mismatch is `mac_mismatch`. |
| P12-011 | The MAC covers the value of the authSafe OCTET STRING as received: with constructed BER, the concatenation of its segments (RFC 7292 §4). |
| P12-012 | MAC digests: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (OIDs of the digests; the HMAC OIDs 1.2.840.113549.2.7–11 are accepted as aliases). Any other algorithm, PBMAC1 included, is `unsupported_algorithm`. |
| P12-013 | The MAC key comes from the PKCS#12 KDF (RFC 7292 appendix B) with ID 3, the MAC digest as hash and the digest length as key length. Absent iterations mean 1. |
| P12-014 | The MAC MUST be compared in constant time. |
| P12-015 | A PFX without MacData MUST be accepted; the decoder reports `mac: null`. Applications that require integrity check that themselves. |
| P12-016 | An authSafe of a content type other than Data (public-key integrity mode) is `unsupported_algorithm`. |

### C. Password

| Rule | Requirement |
|---|---|
| P12-020 | For the PKCS#12 KDF the password, given as UTF-8, is encoded as UTF-16 big-endian with a two-byte zero terminator. Characters outside the BMP become surrogate pairs, as OpenSSL and Java write them. The empty password is `00 00`. |
| P12-021 | PBKDF2 (PBES2) takes the password octets unchanged (RFC 8018 §6.2.1), without terminator. |
| P12-022 | A password that is not valid UTF-8 MAY be mapped byte by byte to UTF-16 units (OpenSSL's fallback). |

### D. Privacy

| Rule | Requirement |
|---|---|
| P12-030 | PBES2 with PBKDF2. PRFs: hmacWithSHA1, -SHA224, -SHA256, -SHA384, -SHA512; absent means hmacWithSHA1. The digest OIDs MAY be accepted as aliases (written by `go/pkcs12` up to v0.99.3). An unknown PRF is `unsupported_algorithm`, never a fallback. |
| P12-031 | PBES2 ciphers: AES-128-CBC, AES-192-CBC, AES-256-CBC with a 16-byte IV. *(legacy)* DES-EDE3-CBC (1.2.840.113549.3.7) with an 8-byte IV. |
| P12-032 | A PBKDF2 keyLength, if present, MUST equal the key size of the cipher; otherwise `malformed`. |
| P12-033 | PKCS#12 PBEs (RFC 7292 appendix C, key and IV from the PKCS#12 KDF with SHA-1, IDs 1 and 2): pbeWithSHAAnd3-KeyTripleDES-CBC. *(legacy)* pbeWithSHAAnd2-KeyTripleDES-CBC (key K1 K2 K1), pbeWithSHAAnd128BitRC2-CBC and pbeWithSHAAnd40BitRC2-CBC (RC2 with 128 and 40 effective key bits). RC4 is `unsupported_algorithm`. |
| P12-034 | Decryption is CBC with PKCS#7 padding. Ciphertext that is empty or not a multiple of the block size, an IV of the wrong size, and padding that is 0, larger than the block size or inconsistent are `decryption_failed`. |
| P12-035 | A safe of a content type other than Data or EncryptedData (public-key privacy mode) is `unsupported_algorithm`. |
| P12-036 | Iteration counts (MAC, PKCS#12 KDF, PBKDF2) MUST be at least 1 (else `malformed`) and MUST NOT exceed 10,000,000; above that the decoder MUST fail with `limit_exceeded` before deriving anything. Producers use 1 to 102,400. |

### E. Bags

| Rule | Requirement |
|---|---|
| P12-040 | A certBag with certId x509Certificate yields the DER certificate (the certValue octets, unchanged). Other certificate types are `unsupported_algorithm`. |
| P12-041 | A pkcs8ShroudedKeyBag yields the decrypted PrivateKeyInfo octets, unchanged; a keyBag yields its PrivateKeyInfo unchanged. |
| P12-042 | A safeContentsBag is decoded recursively. |
| P12-043 | CRL bags, secret bags and unknown bag types are skipped. |
| P12-044 | The attributes friendlyName (BMPString, decoded as UTF-16 so that surrogate pairs written by Windows survive) and localKeyId (OCTET STRING) are reported per bag. Unknown attributes are ignored. |
| P12-045 | A certificate and a key form a pair when both carry the same, non-empty localKeyId. |
| P12-046 | Certificates and keys SHOULD be reported in file order. |

### F. Writing

| Rule | Requirement |
|---|---|
| P12-050 | An encoder MUST write DER, with the elements of every SET OF in DER order. |
| P12-051 | Keys in pkcs8ShroudedKeyBags, certificates in an EncryptedData safe, both with PBES2, PBKDF2 and AES-CBC (default AES-256-CBC, hmacWithSHA256 with NULL parameters); at least 2048 iterations by default; a fresh random salt of at least 8 bytes and a fresh random IV for every encryption. |
| P12-052 | An HMAC MAC with SHA-256, SHA-384 or SHA-512 over the authSafe octets, with a fresh random salt; the digest AlgorithmIdentifier with NULL parameters. |
| P12-053 | friendlyName as BMPString (characters outside the BMP cannot be written), localKeyId as OCTET STRING. |
| P12-054 | An encoder MUST NOT write the legacy algorithms of P12-031 and P12-033, SHA-1 or SHA-224 MACs. |

## Result codes

| Code | Meaning | `go/pkcs12` | `rust/ti-pkcs12` |
|---|---|---|---|
| `ok` | decoded | `nil` | `Ok` |
| `malformed` | not a PKCS#12 file, or a part does not parse | `ErrInvalidPFX`, `ErrParse` | `Error::Malformed` |
| `mac_mismatch` | wrong password or altered file | `ErrAuthentication` | `Error::MacMismatch` |
| `decryption_failed` | ciphertext does not decrypt (wrong password without MAC, corrupt data) | `ErrDecryption` (with `ErrInvalidPadding`) | `Error::DecryptFailed` |
| `unsupported_algorithm` | algorithm or mode outside this specification | `ErrUnsupportedAlgorithm` | `Error::UnsupportedAlgorithm` |
| `limit_exceeded` | iteration count above P12-036 | `ErrLimitExceeded` | `Error::LimitExceeded` |

A wrong password on a file without MAC yields `decryption_failed` in about 255 of 256 cases; in the
others the padding happens to be valid and the plaintext fails to parse (`malformed`). Both are
conformant.

## Algorithm

```text
decode(file, password):
 1. pfx := parse PFX (P12-001; legacy: after BER→DER, P12-002); trailing bytes → malformed (P12-003)
 2. if pfx.authSafe.contentType ≠ Data → unsupported_algorithm (P12-016)
 3. octets := value of the authSafe OCTET STRING, segments joined (P12-011)
 4. if pfx.macData present:
      check iterations (P12-036); hash := MAC digest (P12-012)
      key := PKCS12-KDF(hash, BMP(password), macSalt, iterations, ID 3, |hash|) (P12-013, P12-020)
      HMAC(hash, key, octets) = mac, constant time (P12-014), else mac_mismatch (P12-010)
 5. for each ContentInfo of AuthenticatedSafe(octets):
      Data          → safe := its OCTET STRING value
      EncryptedData → safe := decrypt(contentEncryptionAlgorithm, encryptedContent) (P12-005, D)
      otherwise     → unsupported_algorithm (P12-035)
      collect(SafeContents(safe))
 6. pairs := certificates and keys with equal localKeyId (P12-045)

collect(bags): for each bag
      certBag            → X.509 only (P12-040), with attributes (P12-044)
      pkcs8ShroudedKeyBag → decrypt(EncryptedPrivateKeyInfo) (P12-041)
      keyBag             → PrivateKeyInfo as is (P12-041)
      safeContentsBag    → collect(nested) (P12-042)
      otherwise          → skip (P12-043)

decrypt(algorithm, ciphertext):
      PBES2  → PRF (P12-030), keyLength (P12-032), iterations (P12-036), cipher (P12-031),
               key := PBKDF2(PRF, password octets (P12-021), salt, iterations, key size)
      PKCS#12 PBE → scheme (P12-033), iterations (P12-036),
               key, IV := PKCS12-KDF(SHA-1, BMP(password), salt, iterations, ID 1 / ID 2)
      CBC decrypt, remove padding (P12-034)
```

## Deviations

| Implementation | Rule | Deviation |
|---|---|---|
| `go/pkcs12` up to v0.99.3 | P12-030, P12-051, P12-052 | Wrote the digest OID as PBKDF2 PRF, did not encrypt certificates, had no iteration limit and fell back to SHA-1 for unknown PRFs. Fixed in v0.100.0; such files stay readable (P12-030). |

Third-party libraries are measured, not judged, in [interop/matrix.md](interop/matrix.md).

## Security considerations

- RC2-40, Triple DES and SHA-1 MACs give no meaningful protection against an attacker with the file;
  they are read so that existing card and connector identities stay usable, never written (P12-054).
- A file without MAC can be altered undetected; the decoder reports `mac: null` (P12-015) so that
  applications can refuse it.
- Verifying the MAC first (P12-010) keeps the parsers and decryptors away from attacker-chosen bytes
  in any file whose password the attacker does not know.
- The iteration limit (P12-036) bounds the CPU time a crafted file can cost; it is far above what
  producers use.
- Without MAC, a wrong password is detected by the padding check only, so it is reported as
  `decryption_failed` or `malformed`; decoders MUST NOT return keys from such a file as valid.
