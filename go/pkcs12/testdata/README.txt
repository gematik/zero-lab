PKCS#12 Test Data Files
========================

Generated test files:

1. modern.p12 - Modern PKCS#12 with PBES2/AES-256-CBC/SHA256
   Password: test1234
   Contains: RSA key + certificate + CA cert

2. multi-cert.p12 - Multiple certificates in chain
   Password: test1234
   Contains: RSA key + server cert + CA cert

3. ec.p12 - PKCS#12 with EC key
   Password: test1234
   Contains: EC key (P-256) + certificate

4. no-mac.p12 - No MAC/integrity protection
   Password: test1234
   Contains: RSA key + certificate

5. legacy.p12 - Legacy 3DES encryption
   Password: test1234
   Contains: RSA key + certificate

6. cert-only.p12 - Certificate only, no key
   Password: test1234
   Contains: Certificate only

7. high-iter.p12 - High iteration count (100k)
   Password: test1234
   Contains: RSA key + certificate

8. empty-pass.p12 - Empty password
   Password: (empty)
   Contains: RSA key + certificate

9. aes128.p12 - AES-128-CBC encryption
   Password: test1234
   Contains: RSA key + certificate

Invalid files:
- truncated.p12 - Truncated PKCS#12 file
- random.p12 - Random data
- not-pkcs12.p12 - PEM certificate (not PKCS#12)

All certificates are self-signed test certificates valid for testing only.
