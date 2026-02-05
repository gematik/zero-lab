#!/bin/bash
# generate_test_data.sh - Generate PKCS#12 test files using OpenSSL
# Run this from the testdata directory: cd testdata && ./generate_test_data.sh

set -e

echo "==> Generating CA certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 3650 -nodes \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test CA/CN=Test CA"

# Generate server private key
echo "==> Generating server key and CSR..."
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server-csr.pem \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test/CN=test.example.com"

# Sign server certificate
echo "==> Signing server certificate..."
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365

# Generate EC private key and certificate
echo "==> Generating EC key and certificate..."
openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem
openssl req -new -key ec-key.pem -out ec-csr.pem \
    -subj "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test/CN=ec.example.com"
openssl x509 -req -in ec-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out ec-cert.pem -days 365

# Create certificate chain
cat server-cert.pem ca-cert.pem > chain.pem

echo ""
echo "==> Creating PKCS#12 files..."

# 1. Modern PKCS#12 with AES-256 (PBES2)
echo "  • modern.p12 (AES-256-CBC, SHA-256 MAC)"
openssl pkcs12 -export -out modern.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -certfile ca-cert.pem -passout pass:test123 \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256

# 2. Legacy 3DES
echo "  • legacy.p12 (3DES, SHA-1 MAC)"
openssl pkcs12 -export -out legacy.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass:test123 -legacy

# 3. AES-128
echo "  • aes128.p12 (AES-128-CBC)"
openssl pkcs12 -export -out aes128.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass:test123 -keypbe AES-128-CBC -certpbe AES-128-CBC

# 4. EC key
echo "  • ec.p12 (EC key with AES-256)"
openssl pkcs12 -export -out ec.p12 \
    -inkey ec-key.pem -in ec-cert.pem \
    -passout pass:test123 -keypbe AES-256-CBC -certpbe AES-256-CBC

# 5. Multiple certificates (chain)
echo "  • multi-cert.p12 (certificate chain)"
openssl pkcs12 -export -out multi-cert.p12 \
    -inkey server-key.pem -in chain.pem \
    -passout pass:test123 -keypbe AES-256-CBC -certpbe AES-256-CBC

# 6. Certificate only (no private key)
echo "  • cert-only.p12 (no private key)"
openssl pkcs12 -export -out cert-only.p12 \
    -nokeys -in server-cert.pem \
    -passout pass:test123

# 7. Empty password
echo "  • empty-pass.p12 (empty password)"
openssl pkcs12 -export -out empty-pass.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass: -keypbe AES-256-CBC -certpbe AES-256-CBC

# 8. No MAC
echo "  • no-mac.p12 (no MAC)"
openssl pkcs12 -export -out no-mac.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass:test123 -keypbe AES-256-CBC -certpbe AES-256-CBC -nomac

# 9. High iteration count
echo "  • high-iter.p12 (10000 iterations)"
openssl pkcs12 -export -out high-iter.p12 \
    -inkey server-key.pem -in server-cert.pem \
    -passout pass:test123 -keypbe AES-256-CBC -certpbe AES-256-CBC -iter 10000

# 10. Invalid files for negative testing
echo "  • not-pkcs12.p12 (invalid: just a cert)"
cp server-cert.pem not-pkcs12.p12

echo "  • random.p12 (invalid: random data)"
dd if=/dev/urandom of=random.p12 bs=1024 count=1 2>/dev/null

echo ""
echo "==> Test data generation complete!"
echo "Generated $(ls -1 *.p12 | wc -l) PKCS#12 files in testdata/"
