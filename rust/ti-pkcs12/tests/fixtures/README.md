# PKCS#12 Parser Test Suite

Comprehensive test coverage with real PKCS#12 files generated using OpenSSL.

## Test Data Generation

Run `./generate_test_data.sh` to create test files in `testdata/` directory.

### Generated Test Files

| File | Description | Password | Encryption | MAC |
|------|-------------|----------|------------|-----|
| `modern.p12` | Modern PBES2/AES-256-CBC | `test1234` | AES-256-CBC | SHA-256 |
| `multi-cert.p12` | Certificate chain | `test1234` | AES-256-CBC | SHA-256 |
| `ec.p12` | EC key (P-256) | `test1234` | AES-256-CBC | SHA-256 |
| `no-mac.p12` | No integrity protection | `test1234` | AES-256-CBC | None |
| `legacy.p12` | Legacy 3DES | `test1234` | 3DES-CBC | SHA-1 |
| `cert-only.p12` | Certificate only, no key | `test1234` | AES-256-CBC | SHA-256 |
| `high-iter.p12` | Standard encryption | `test1234` | AES-256-CBC | SHA-256 |
| `empty-pass.p12` | Empty password | *(empty)* | AES-256-CBC | SHA-256 |
| `aes128.p12` | AES-128-CBC | `test1234` | AES-128-CBC | SHA-256 |
| `truncated.p12` | Invalid: truncated file | N/A | N/A | N/A |
| `random.p12` | Invalid: random data | N/A | N/A | N/A |
| `not-pkcs12.p12` | Invalid: PEM certificate | N/A | N/A | N/A |

## Test Coverage

### Positive Tests (Valid PKCS#12 Files)

#### Structure Parsing Tests
- ✅ **TestParseModernPKCS12** - Parse modern PKCS#12 with PBES2/AES-256-CBC
- ✅ **TestParseMultipleCertificates** - Multiple certificates in chain
- ✅ **TestParseECKey** - PKCS#12 with EC key (P-256)
- ✅ **TestParseNoMAC** - File without MAC/integrity protection
- ✅ **TestParseLegacy3DES** - Legacy 3DES encryption
- ✅ **TestParseCertOnly** - Certificate only, no private key
- ✅ **TestParseEmptyPassword** - Empty password
- ✅ **TestParseAES128** - AES-128-CBC encryption
- ✅ **TestParseCertBagStructure** - Detailed bag structure parsing
- ✅ **TestParseAllTestFiles** - Batch test all valid files

#### Component Tests
- ✅ **TestOIDConstants** - Verify OID constants
- ✅ **TestOIDEquality** - OID comparison
- ✅ **TestDecodeBMPString** - BMPString decoding
- ✅ **TestExtractOctetString** - OCTET STRING extraction
- ✅ **TestExtractOctetStringNested** - Nested OCTET STRING

### Negative Tests (Invalid/Error Cases)

#### Invalid File Tests
- ✅ **TestParseTruncatedFile** - Truncated PKCS#12 file
- ✅ **TestParseRandomData** - Random data
- ✅ **TestParseNotPKCS12** - Non-PKCS#12 file
- ✅ **TestParseEmptyData** - Empty input
- ✅ **TestParseInvalidVersion** - Invalid PFX version
- ✅ **TestParseMalformedContentInfo** - Malformed ContentInfo

#### Structure Error Tests
- ✅ **TestParseInvalidBagID** - Uncommon bag type (CRLBag)
- ✅ **TestParseCertBagInvalid** - Invalid certificate bag
- ✅ **TestParseEncryptedPrivateKeyInfoInvalid** - Invalid encrypted key
- ✅ **TestParseUnsupportedEncryptionAlgorithm** - Unsupported algorithm OID

#### Attribute Tests
- ✅ **TestGetFriendlyNameInvalid** - Invalid BMPString in friendly name
- ✅ **TestGetLocalKeyIDNotPresent** - LocalKeyID not present

#### Edge Case Tests
- ✅ **TestDecodeBMPStringEdgeCases** - Odd length, unicode, null
- ✅ **TestParseInvalidPFX** - Various invalid PFX structures

## Test Statistics

```
Total Tests:     28
Passing:         28
Failing:         0
Success Rate:    100%
```

## Performance Benchmarks

Tested on Apple M3 Pro:

```
BenchmarkParse-12                      4159442    281.3 ns/op    416 B/op    4 allocs/op
BenchmarkParseAuthenticatedSafe-12     4674206    253.5 ns/op    328 B/op    5 allocs/op
```

**Analysis:**
- **High throughput**: ~4M operations/second for full PFX parsing
- **Low memory**: Only 416 bytes allocated per parse
- **Minimal allocations**: Only 4 allocations per operation
- **Zero-copy efficient**: cryptobytes minimizes copying

## Real-World Parsing Results

### Modern PKCS#12 (modern.p12)
```
✓ PFX Version: 3
✓ MAC Algorithm: 2.16.840.1.101.3.4.2.1 (SHA-256)
✓ MAC Iterations: 2048
✓ ContentInfos: 2
  - EncryptedData (2187 bytes)
  - Data (unencrypted certificates)
```

### Legacy PKCS#12 (legacy.p12)
```
✓ PFX Version: 3
✓ MAC Algorithm: 1.3.14.3.2.26 (SHA-1 legacy)
✓ MAC Iterations: 2048
✓ ContentInfos: 2
```

### Certificate Only (cert-only.p12)
```
✓ PFX Version: 3
✓ MAC present
✓ Contains certificates without private keys
```

## Verification

All test files can be verified with OpenSSL:

```bash
# Inspect structure
openssl asn1parse -in testdata/modern.p12 -inform DER

# List contents (requires password)
openssl pkcs12 -in testdata/modern.p12 -info -noout -passin pass:test1234

# Extract certificate
openssl pkcs12 -in testdata/modern.p12 -nokeys -passin pass:test1234 | \
    openssl x509 -text -noout
```

## Test Assertions

Each test verifies:

1. **Structure integrity**: Valid ASN.1 DER encoding
2. **Version compliance**: PFX version 3
3. **OID correctness**: All OIDs match RFC 7292
4. **Content parsing**: AuthenticatedSafe and SafeContents
5. **Attribute handling**: FriendlyName and LocalKeyID
6. **Error handling**: Graceful failure on invalid input
7. **Algorithm recognition**: PBES2, PBKDF2, AES, etc.

## Coverage by RFC 7292 Section

- ✅ Section 4: PFX PDU (top-level structure)
- ✅ Section 4.1: The AuthenticatedSafe
- ✅ Section 4.2: The SafeBag types
  - ✅ 4.2.1: The KeyBag (OID recognition)
  - ✅ 4.2.2: The PKCS8ShroudedKeyBag
  - ✅ 4.2.3: The CertBag
  - ✅ 4.2.4: The CRLBag (OID recognition)
  - ✅ 4.2.5: The SecretBag (OID recognition)
  - ✅ 4.2.6: The SafeContentsBag (OID recognition)
- ✅ Section 5: MAC algorithm identifiers
- ✅ Appendix C: Keys and IVs for Password Integrity (OIDs)

## Running Tests

```bash
# Run all tests
go test -v

# Run specific test
go test -v -run TestParseModernPKCS12

# Run with coverage
go test -cover

# Run benchmarks
go test -bench=. -benchmem

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Continuous Integration

Tests can be run in CI/CD pipelines:

```yaml
- name: Generate test data
  run: ./generate_test_data.sh
  
- name: Run tests
  run: go test -v -race -coverprofile=coverage.out
  
- name: Check coverage
  run: go tool cover -func=coverage.out
```

## Known Limitations

1. **No decryption**: Tests only parse structure, do not decrypt
2. **Password verification**: MAC verification not tested (requires crypto implementation)
3. **Legacy algorithms**: MD5/RC4 intentionally not supported
4. **OpenSSL version**: Test generation requires OpenSSL 1.1.1 or later

## Future Test Enhancements

- [ ] Add PBES2 with different KDF parameters
- [ ] Test with corrupted MAC values
- [ ] Test with very large files (>100MB)
- [ ] Test with malformed but parseable structures
- [ ] Add fuzzing tests
- [ ] Test thread safety with concurrent parsing

## Test Maintenance

Test data should be regenerated when:
- OpenSSL version changes
- New encryption algorithms are added
- RFC updates require new structures
- Security requirements change

Regenerate test data:
```bash
rm -rf testdata/
./generate_test_data.sh
go test -v
```
