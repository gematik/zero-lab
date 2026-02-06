# pkcs12 CLI Tool

A command-line tool for working with PKCS#12 (.p12/.pfx) files.

## Installation

```bash
go install github.com/gematik/zero-lab/go/pkcs12/cmd/pkcs12@latest
```

Or build from source:

```bash
cd cmd/pkcs12
go build
```

## Commands

### info - Display PKCS#12 file information

Display comprehensive information about a PKCS#12 file:

```bash
pkcs12 info keystore.p12
```

With password on command line:

```bash
pkcs12 info keystore.p12 --password mypassword
```

The tool displays:
- PKCS#12 structure (version, MAC info)
- Content infos (encrypted/unencrypted)
- MAC verification status
- All certificates with details (subject, issuer, validity, key type)
- All private keys with type information
- Matching certificate/key pairs

### create - Create new PKCS#12 file

Create a PKCS#12 file from certificate(s) and optional private key:

```bash
# Certificate and key
pkcs12 create --cert cert.pem --key key.pem --output keystore.p12

# Multiple certificates (e.g., certificate + CA chain)
pkcs12 create --cert cert.pem --cert ca.pem --key key.pem --output keystore.p12

# Certificate chain from single file
pkcs12 create --cert chain.pem --key key.pem --output keystore.p12

# Certificate only (no key)
pkcs12 create --cert cert.pem --output certs-only.p12
```

With password on command line:

```bash
pkcs12 create --cert cert.pem --key key.pem --output keystore.p12 --password secret
```

With friendly name:

```bash
pkcs12 create --cert cert.pem --key key.pem --output keystore.p12 --name "My Certificate"
```

**Note:** Private key must be in PKCS#8 format. Convert if needed:

```bash
openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem
```

## Options

### Info Command

- `--password string` - Password (if not provided, will prompt securely)

### Create Command

- `--cert string` - Certificate file (PEM or DER format), can be specified multiple times
- `--key string` - Private key file (PEM or DER, PKCS#8 format, optional)
- `--output string` - Output PKCS#12 file path (required)
- `--password string` - Password (if not provided, will prompt securely)
- `--name string` - Friendly name for first certificate and key

## Features

### Multiple Certificates

The `--cert` flag can be specified multiple times to include multiple certificates:

```bash
pkcs12 create \
  --cert server.pem \
  --cert intermediate.pem \
  --cert root.pem \
  --key server-key.pem \
  --output fullchain.p12
```

### Certificate Chains

If a PEM file contains multiple certificates, they are all included:

```bash
# chain.pem contains: server cert + intermediate + root
pkcs12 create --cert chain.pem --key key.pem --output keystore.p12
```

### Certificate-Only P12

Private key is optional - create certificate-only PKCS#12 files:

```bash
pkcs12 create --cert cert.pem --cert ca.pem --output certs.p12
```

## Security

- Uses AES-256-CBC encryption for keys
- SHA-256 MAC for integrity
- 2048 PBKDF2 iterations
- Passwords are prompted securely (not echoed to terminal)
- Created files have 0600 permissions (owner read/write only)

## Examples

### Inspect a PKCS#12 file

```bash
$ pkcs12 info keystore.p12
Enter password: 
=== PKCS#12 Structure ===
File: keystore.p12
Size: 2639 bytes
Version: 3
Has MAC: true

=== MAC Verification ===
✅ MAC verified successfully

=== Certificates (2) ===

Certificate #1:
  FriendlyName: My Certificate
  LocalKeyID: 01020304
  Subject: CN=example.com
  Issuer: CN=Intermediate CA
  ...

Certificate #2:
  Subject: CN=Intermediate CA
  Issuer: CN=Root CA
  ...

=== Private Keys (1) ===

Private Key #1:
  FriendlyName: My Certificate
  LocalKeyID: 01020304
  Type: *rsa.PrivateKey
  Size: 1192 bytes (DER)
```

### Create a PKCS#12 with certificate chain

```bash
$ pkcs12 create --cert server.pem --cert ca.pem --key key.pem --output keystore.p12
✓ Loaded certificate: CN=server.example.com
✓ Loaded certificate: CN=CA
✓ Loaded private key: *rsa.PrivateKey
Enter password for new PKCS#12 file: 

✅ PKCS#12 file created successfully: keystore.p12
   Certificates: 2
   Private Keys: 1
   Size: 3635 bytes
   Encryption: AES-256-CBC
   MAC: SHA-256
```

### Create certificate-only PKCS#12

```bash
$ pkcs12 create --cert cert1.pem --cert cert2.pem --output certs.p12
✓ Loaded certificate: CN=cert1.example.com
✓ Loaded certificate: CN=cert2.example.com
Enter password for new PKCS#12 file: 

✅ PKCS#12 file created successfully: certs.p12
   Certificates: 2
   Private Keys: 0
   Size: 1434 bytes
   Encryption: AES-256-CBC
   MAC: SHA-256
```

## Exit Codes

- `0` - Success
- `1` - Error (invalid input, parsing failure, etc.)

## Troubleshooting

### BER Indefinite-Length Encoding

**Error:**
```
Error parsing PKCS#12: BER indefinite-length encoding detected (0x30 0x80)
```

**Cause:** File uses BER (Basic Encoding Rules) instead of DER (Distinguished Encoding Rules)

**Solution for OpenSSL 3.x with legacy algorithms:**

```bash
# Extract (may need -legacy for old encryption algorithms)
openssl pkcs12 -in file.p12 -out temp.pem -nodes -passin pass:PASSWORD -legacy

# Re-encode to DER
openssl pkcs12 -export -in temp.pem -out fixed.p12 -passout pass:PASSWORD

# Clean up
rm temp.pem
```

**Solution for OpenSSL 1.x or modern algorithms:**

```bash
openssl pkcs12 -in file.p12 -out temp.pem -nodes -passin pass:PASSWORD
openssl pkcs12 -export -in temp.pem -out fixed.p12 -passout pass:PASSWORD
rm temp.pem
```

**Note:** If the file has no password, use empty password (just press Enter when prompted)

### Legacy Algorithms

OpenSSL 3.0+ deprecated legacy algorithms (RC2, RC4, MD5). Add `-legacy` flag:

```bash
openssl pkcs12 -in old.p12 -legacy -passin pass:PASSWORD
```

**This library supports:**
- ✅ Modern: PBES2/AES-128/192/256, PBKDF2, SHA-256/384/512
- ✅ Legacy compatibility: 3DES-CBC, SHA-1 MAC  
- ❌ Not supported: MD5, RC4, single-DES, weak RC2

