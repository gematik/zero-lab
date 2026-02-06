# legacy - BER/Legacy PKCS#12 Converter

This package provides OpenSSL-based utilities to convert BER-encoded (legacy) PKCS#12 files to DER format.

## Problem

The main `pkcs12` package requires DER encoding (RFC 7292 mandate). However, legacy PKCS#12 files (from Windows, Java keystores, older OpenSSL versions) often use BER indefinite-length encoding, causing parsing to fail.

## Solution

This package provides an OpenSSL-based converter that reliably converts BER→DER while preserving MAC integrity:

```go
// Check if file is BER
if legacy.IsBER(data) {
    // Convert BER to DER using OpenSSL
    derData, err := legacy.ConvertWithOpenSSL(berData, password)
    if err != nil {
        log.Fatal(err)
    }
    
    // Now parse with main package
    pfx, err := pkcs12.Parse(derData)
    if err != nil {
        log.Fatal(err)
    }
}
```

## API

### `IsBER(data []byte) bool`
Detects if data is BER-encoded by checking for the indefinite-length SEQUENCE tag (0x30 0x80).

### `ConvertWithOpenSSL(berData []byte, password string) ([]byte, error)`
Converts BER-encoded PKCS#12 to DER format using OpenSSL command-line tool.

This is the recommended (and only) approach because it:
- Reliably handles complex legacy formats
- Preserves MAC integrity
- Works with all standard PKCS#12 structures

## Requirements

- OpenSSL 3.x installed and in PATH
- OpenSSL must support the `-legacy` flag for BER decoding

## Testing

The package includes integration tests with real PKCS#12 files:
- `cgm.p12` - CGM KoCo Konnektor Client Cert (password in `cgm-password.txt`)
- `secunet.p12` - Secunet Konnektor Client Cert (password in `secunet-password.txt`)

Run tests with:
```bash
go test -v
```

