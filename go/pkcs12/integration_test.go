package pkcs12

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestParseModernPKCS12 tests parsing a modern PKCS#12 file with PBES2/AES-256-CBC
func TestParseModernPKCS12(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse modern.p12: %v", err)
	}

	// Verify PFX structure
	if pfx.Version != 3 {
		t.Errorf("Expected version 3, got %d", pfx.Version)
	}

	// Verify MAC is present
	if pfx.MacData == nil {
		t.Error("Expected MacData to be present")
	} else {
		// Verify MAC algorithm (should be SHA-256 or HMAC-SHA256)
		macAlg := pfx.MacData.Mac.Algorithm.Algorithm
		if !macAlg.Equal(OIDHMACSHA256) && !macAlg.Equal(OIDSHA256) {
			t.Logf("Note: MAC algorithm is %v (expected SHA-256)", macAlg)
		}

		if len(pfx.MacData.MacSalt) == 0 {
			t.Error("MacSalt should not be empty")
		}

		if pfx.MacData.Iterations < 1 {
			t.Errorf("Iterations should be >= 1, got %d", pfx.MacData.Iterations)
		}
	}

	// Verify AuthSafe ContentType
	if !pfx.AuthSafe.ContentType.Equal(OIDData) {
		t.Errorf("Expected authSafe type to be Data, got %v", pfx.AuthSafe.ContentType)
	}

	// Parse authenticated safe
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("PFX Version: %d", pfx.Version)
	t.Logf("MAC Algorithm: %v", pfx.MacData.Mac.Algorithm.Algorithm)
	t.Logf("MAC Iterations: %d", pfx.MacData.Iterations)
	t.Logf("ContentInfos count: %d", len(authSafe.ContentInfos))
}

// TestParseMultipleCertificates tests PKCS#12 with multiple certificates
func TestParseMultipleCertificates(t *testing.T) {
	data := loadTestFile(t, "testdata/multi-cert.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse multi-cert.p12: %v", err)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	certCount := 0
	keyCount := 0

	for i, ci := range authSafe.ContentInfos {
		t.Logf("ContentInfo[%d]: %v", i, ci.ContentType)

		// For this test, we expect encrypted data
		if ci.ContentType.Equal(OIDEncryptedData) {
			// In a real scenario, you'd decrypt here with password
			// For now, just verify structure
			t.Logf("  Encrypted content (length: %d bytes)", len(ci.Content))
		} else if ci.ContentType.Equal(OIDData) {
			// Unencrypted data
			content, err := extractOctetString(ci.Content)
			if err != nil {
				t.Logf("  Warning: Failed to extract data: %v", err)
				continue
			}

			sc, err := ParseSafeContents(content)
			if err != nil {
				t.Logf("  Warning: Failed to parse safe contents: %v", err)
				continue
			}

			for _, bag := range sc.Bags {
				if bag.BagID.Equal(OIDCertBag) {
					certCount++
				} else if bag.BagID.Equal(OIDPKCS8ShroudedKeyBag) {
					keyCount++
				}
			}
		}
	}

	t.Logf("Found %d certificates (in unencrypted bags), %d keys", certCount, keyCount)
}

// TestParseECKey tests PKCS#12 with EC key
func TestParseECKey(t *testing.T) {
	data := loadTestFile(t, "testdata/ec.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse ec.p12: %v", err)
	}

	if pfx.Version != 3 {
		t.Errorf("Expected version 3, got %d", pfx.Version)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("Successfully parsed EC key PKCS#12 file")
}

// TestParseNoMAC tests PKCS#12 without MAC
func TestParseNoMAC(t *testing.T) {
	data := loadTestFile(t, "testdata/no-mac.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse no-mac.p12: %v", err)
	}

	if pfx.MacData != nil {
		t.Error("Expected MacData to be nil for file without MAC")
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("Successfully parsed PKCS#12 without MAC")
}

// TestParseLegacy3DES tests legacy PKCS#12 with 3DES
func TestParseLegacy3DES(t *testing.T) {
	data := loadTestFile(t, "testdata/legacy.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse legacy.p12: %v", err)
	}

	// Legacy file should have SHA-1 MAC
	if pfx.MacData != nil {
		if !pfx.MacData.Mac.Algorithm.Algorithm.Equal(OIDHMACSHA1) {
			t.Logf("Note: MAC algorithm is %v (expected SHA-1 for legacy)",
				pfx.MacData.Mac.Algorithm.Algorithm)
		}
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("Successfully parsed legacy PKCS#12 file")
}

// TestParseCertOnly tests PKCS#12 with certificate only (no key)
func TestParseCertOnly(t *testing.T) {
	data := loadTestFile(t, "testdata/cert-only.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse cert-only.p12: %v", err)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("Successfully parsed certificate-only PKCS#12")
}

// TestParseEmptyPassword tests PKCS#12 with empty password
func TestParseEmptyPassword(t *testing.T) {
	data := loadTestFile(t, "testdata/empty-pass.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse empty-pass.p12: %v", err)
	}

	if pfx.Version != 3 {
		t.Errorf("Expected version 3, got %d", pfx.Version)
	}

	t.Logf("Successfully parsed PKCS#12 with empty password")
}

// TestParseAES128 tests PKCS#12 with AES-128-CBC
func TestParseAES128(t *testing.T) {
	data := loadTestFile(t, "testdata/aes128.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse aes128.p12: %v", err)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	if len(authSafe.ContentInfos) == 0 {
		t.Error("Expected at least one ContentInfo")
	}

	t.Logf("Successfully parsed AES-128 PKCS#12")
}

// TestParseCertBagStructure tests parsing certificate bags
// Note: Modern PKCS#12 files typically encrypt the contents, so this test
// demonstrates the structure even though we can't decrypt without password
func TestParseCertBagStructure(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")

	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}

	foundEncrypted := false
	foundUnencrypted := false

	for _, ci := range authSafe.ContentInfos {
		t.Logf("ContentInfo type: %v", ci.ContentType)

		if ci.ContentType.Equal(OIDEncryptedData) {
			foundEncrypted = true
			t.Logf("  Found encrypted data (requires password to decrypt)")
			// In real usage, decrypt here with password
		} else if ci.ContentType.Equal(OIDData) {
			foundUnencrypted = true
			content, err := extractOctetString(ci.Content)
			if err != nil {
				t.Logf("  Warning: Failed to extract data: %v", err)
				continue
			}

			sc, err := ParseSafeContents(content)
			if err != nil {
				t.Logf("  Warning: Failed to parse safe contents: %v", err)
				continue
			}

			for _, bag := range sc.Bags {
				t.Logf("  Bag type: %v", bag.BagID)

				if bag.BagID.Equal(OIDCertBag) {
					certBag, err := ParseCertBag(bag.BagValue)
					if err != nil {
						t.Errorf("Failed to parse cert bag: %v", err)
						continue
					}

					if !certBag.CertID.Equal(OIDX509Certificate) {
						t.Errorf("Expected X509 certificate, got %v", certBag.CertID)
					}

					// Try to parse the certificate
					cert, err := x509.ParseCertificate(certBag.CertValue)
					if err != nil {
						t.Errorf("Failed to parse X.509 certificate: %v", err)
					} else {
						t.Logf("  Certificate Subject: %s", cert.Subject)
					}

					// Check attributes
					if name, ok := GetFriendlyName(bag.Attributes); ok {
						t.Logf("  Friendly name: %s", name)
					}

					if keyID, ok := GetLocalKeyID(bag.Attributes); ok {
						t.Logf("  Local key ID: %x", keyID)
					}
				}

				if bag.BagID.Equal(OIDPKCS8ShroudedKeyBag) {
					epki, err := ParseEncryptedPrivateKeyInfo(bag.BagValue)
					if err != nil {
						t.Errorf("Failed to parse encrypted key info: %v", err)
						continue
					}

					t.Logf("  Encryption algorithm: %v", epki.Algorithm.Algorithm)

					// Try to parse encryption algorithm
					encAlg, err := ParseEncryptionAlgorithm(epki.Algorithm)
					if err != nil {
						t.Logf("  Note: %v", err)
					} else {
						t.Logf("  Parsed encryption algorithm: %v", encAlg.Algorithm)

						if encAlg.KDF != nil {
							t.Logf("    KDF iterations: %d", encAlg.KDF.Iterations)
						}

						if encAlg.Cipher != nil {
							t.Logf("    Cipher: %v", encAlg.Cipher.Algorithm)
						}
					}
				}
			}
		}
	}

	if !foundEncrypted && !foundUnencrypted {
		t.Error("No content found in authenticated safe")
	}

	t.Logf("Summary: encrypted=%v, unencrypted=%v", foundEncrypted, foundUnencrypted)
}

// TestParseAllTestFiles tests parsing all valid test files
func TestParseAllTestFiles(t *testing.T) {
	validFiles := []string{
		"modern.p12",
		"multi-cert.p12",
		"ec.p12",
		"no-mac.p12",
		"legacy.p12",
		"cert-only.p12",
		"high-iter.p12",
		"empty-pass.p12",
		"aes128.p12",
	}

	for _, filename := range validFiles {
		t.Run(filename, func(t *testing.T) {
			data := loadTestFile(t, filepath.Join("testdata", filename))

			pfx, err := Parse(data)
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", filename, err)
			}

			if pfx.Version != 3 {
				t.Errorf("Expected version 3, got %d", pfx.Version)
			}

			// Verify we can parse authenticated safe
			_, err = ParseAuthenticatedSafe(pfx.RawAuthSafe)
			if err != nil {
				t.Errorf("Failed to parse authenticated safe: %v", err)
			}
		})
	}
}

// Negative tests

// TestParseTruncatedFile tests parsing truncated PKCS#12 file
func TestParseTruncatedFile(t *testing.T) {
	data := loadTestFile(t, "testdata/truncated.p12")

	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for truncated file, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestParseRandomData tests parsing random data
func TestParseRandomData(t *testing.T) {
	data := loadTestFile(t, "testdata/random.p12")

	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for random data, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestParseNotPKCS12 tests parsing non-PKCS#12 file
func TestParseNotPKCS12(t *testing.T) {
	data := loadTestFile(t, "testdata/not-pkcs12.p12")

	_, err := Parse(data)
	if err == nil {
		t.Error("Expected error for non-PKCS#12 file, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestParseEmptyData tests parsing empty data
func TestParseEmptyData(t *testing.T) {
	_, err := Parse([]byte{})
	if err == nil {
		t.Error("Expected error for empty data, got nil")
	}
}

// TestParseInvalidVersion tests handling of invalid version
func TestParseInvalidVersion(t *testing.T) {
	// Construct a PFX with invalid version
	// PFX SEQUENCE with version 2 instead of 3
	invalidPFX := []byte{
		0x30, 0x10, // SEQUENCE
		0x02, 0x01, 0x02, // INTEGER 2 (invalid version)
		0x30, 0x0B, // ContentInfo SEQUENCE
		0x06, 0x09, // OID
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, // data OID
	}

	_, err := Parse(invalidPFX)
	if err == nil {
		t.Error("Expected error for invalid version, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestParseMalformedContentInfo tests malformed ContentInfo
func TestParseMalformedContentInfo(t *testing.T) {
	malformed := []byte{
		0x30, 0x0A, // SEQUENCE
		0x02, 0x01, 0x03, // INTEGER 3 (version)
		0x30, 0x05, // ContentInfo SEQUENCE (too short)
		0x06, 0x03, 0x00, 0x00, 0x00, // Invalid OID
	}

	_, err := Parse(malformed)
	if err == nil {
		t.Error("Expected error for malformed ContentInfo, got nil")
	}
}

// TestParseInvalidBagID tests SafeBag with unknown bag type
func TestParseInvalidBagID(t *testing.T) {
	// Use a valid but uncommon OID (not one of the standard PKCS#12 bag types)
	// Using OID for CRL bag which is valid but uncommon
	uncommonOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}

	// Build a simple SafeBag structure manually using standard encoding/asn1
	type simpleBag struct {
		BagID    asn1.ObjectIdentifier
		BagValue asn1.RawValue `asn1:"tag:0,explicit"`
		Attrs    asn1.RawValue `asn1:"set,optional,omitempty"`
	}

	// Create a minimal bag value
	bagValue := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x04, 0x00}, // Empty octet string
	}

	bag := simpleBag{
		BagID:    uncommonOID,
		BagValue: bagValue,
	}

	bagEncoded, err := asn1.Marshal(bag)
	if err != nil {
		t.Fatalf("Failed to marshal bag: %v", err)
	}

	// Wrap in sequence for SafeContents
	safeContents, err := asn1.Marshal([]asn1.RawValue{{FullBytes: bagEncoded}})
	if err != nil {
		t.Fatalf("Failed to marshal safe contents: %v", err)
	}

	// This should parse successfully (uncommon OID is fine, caller handles it)
	sc, err := ParseSafeContents(safeContents)
	if err != nil {
		t.Fatalf("Failed to parse safe contents with uncommon OID: %v", err)
	}

	if len(sc.Bags) != 1 {
		t.Errorf("Expected 1 bag, got %d", len(sc.Bags))
	}

	if len(sc.Bags) > 0 && !sc.Bags[0].BagID.Equal(uncommonOID) {
		t.Errorf("Bag ID mismatch: got %v, want %v", sc.Bags[0].BagID, uncommonOID)
	}

	t.Logf("Successfully parsed bag with uncommon OID (CRLBag): %v", uncommonOID)
}

// TestGetFriendlyNameInvalid tests GetFriendlyName with invalid data
func TestGetFriendlyNameInvalid(t *testing.T) {
	attrs := []PKCS12Attribute{
		{
			ID:     OIDFriendlyName,
			Values: [][]byte{{0x00, 0x01, 0x02}}, // Invalid BMPString
		},
	}

	_, ok := GetFriendlyName(attrs)
	if ok {
		t.Error("Expected failure for invalid BMPString, got success")
	}
}

// TestGetLocalKeyIDNotPresent tests GetLocalKeyID when not present
func TestGetLocalKeyIDNotPresent(t *testing.T) {
	attrs := []PKCS12Attribute{
		{
			ID:     OIDFriendlyName,
			Values: [][]byte{},
		},
	}

	_, ok := GetLocalKeyID(attrs)
	if ok {
		t.Error("Expected false when LocalKeyID not present")
	}
}

// TestParseCertBagInvalid tests parsing invalid cert bag
func TestParseCertBagInvalid(t *testing.T) {
	invalidData := []byte{0x30, 0x00} // Empty sequence

	_, err := ParseCertBag(invalidData)
	if err == nil {
		t.Error("Expected error for invalid cert bag, got nil")
	}
}

// TestParseEncryptedPrivateKeyInfoInvalid tests invalid encrypted key info
func TestParseEncryptedPrivateKeyInfoInvalid(t *testing.T) {
	invalidData := []byte{0x04, 0x02, 0x00, 0x00} // Octet string, not sequence

	_, err := ParseEncryptedPrivateKeyInfo(invalidData)
	if err == nil {
		t.Error("Expected error for invalid encrypted key info, got nil")
	}
}

// TestParseUnsupportedEncryptionAlgorithm tests unsupported algorithm
func TestParseUnsupportedEncryptionAlgorithm(t *testing.T) {
	unsupportedOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	alg := asn1.RawValue{
		Tag:   asn1.TagSequence,
		Bytes: []byte{},
	}

	_, err := ParseEncryptionAlgorithm(pkix.AlgorithmIdentifier{
		Algorithm:  unsupportedOID,
		Parameters: alg,
	})

	if err == nil {
		t.Error("Expected error for unsupported algorithm, got nil")
	}

	// Check that error wraps ErrUnsupportedAlgorithm
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("Expected error to wrap ErrUnsupportedAlgorithm, got %v", err)
	}
}

// TestDecodeBMPStringEdgeCases tests BMPString edge cases
func TestDecodeBMPStringEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "odd length",
			input:   []byte{0x00},
			wantErr: true,
		},
		{
			name:    "unicode characters",
			input:   []byte{0x00, 0x41, 0x00, 0x42, 0x03, 0xC0}, // AB + Greek letter
			wantErr: false,
		},
		{
			name:    "null character",
			input:   []byte{0x00, 0x00},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeBMPString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeBMPString() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				t.Logf("Decoded: %q", result)
			}
		})
	}
}

// TestExtractOctetStringNested tests nested octet strings
func TestExtractOctetStringNested(t *testing.T) {
	// OCTET STRING containing another OCTET STRING
	inner := []byte{0x04, 0x02, 0xAA, 0xBB}
	outer := append([]byte{0x04, byte(len(inner))}, inner...)

	result, err := extractOctetString(outer)
	if err != nil {
		t.Fatalf("Failed to extract octet string: %v", err)
	}

	// Should extract the inner OCTET STRING as-is
	if !bytes.Equal(result, inner) {
		t.Errorf("Expected %x, got %x", inner, result)
	}
}

// Helper function to load test files
func loadTestFile(t testing.TB, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read test file %s: %v", path, err)
	}

	return data
}

// BenchmarkParse benchmarks PKCS#12 parsing
func BenchmarkParse(b *testing.B) {
	data, err := os.ReadFile("testdata/modern.p12")
	if err != nil {
		b.Skipf("Test file not available: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(data)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

// BenchmarkParseAuthenticatedSafe benchmarks authenticated safe parsing
func BenchmarkParseAuthenticatedSafe(b *testing.B) {
	data, err := os.ReadFile("testdata/modern.p12")
	if err != nil {
		b.Skipf("Test file not available: %v", err)
	}

	pfx, err := Parse(data)
	if err != nil {
		b.Fatalf("Parse failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
		if err != nil {
			b.Fatalf("ParseAuthenticatedSafe failed: %v", err)
		}
	}
}
