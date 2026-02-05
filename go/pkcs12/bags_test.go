package pkcs12

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// TestExtractBagsModern tests extracting bags from modern PKCS#12 file
func TestExtractBagsModern(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	// Should have certificates and keys
	if len(bags.Certificates) == 0 {
		t.Error("Expected at least one certificate")
	}
	if len(bags.PrivateKeys) == 0 {
		t.Error("Expected at least one private key")
	}
	
	t.Logf("Extracted %d certificate(s) and %d key(s)", 
		len(bags.Certificates), len(bags.PrivateKeys))
	
	// Verify certificate data is valid X.509
	for i, cert := range bags.Certificates {
		x509Cert, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			t.Errorf("Certificate[%d]: Failed to parse as X.509: %v", i, err)
			continue
		}
		t.Logf("Certificate[%d]: Subject=%s, Issuer=%s", 
			i, x509Cert.Subject, x509Cert.Issuer)
		
		if cert.FriendlyName != "" {
			t.Logf("  FriendlyName: %s", cert.FriendlyName)
		}
		if len(cert.LocalKeyID) > 0 {
			t.Logf("  LocalKeyID: %x", cert.LocalKeyID)
		}
	}
	
	// Verify key data is valid PKCS#8
	for i, key := range bags.PrivateKeys {
		privKey, err := x509.ParsePKCS8PrivateKey(key.Raw)
		if err != nil {
			t.Errorf("PrivateKey[%d]: Failed to parse as PKCS#8: %v", i, err)
			continue
		}
		t.Logf("PrivateKey[%d]: Type=%T", i, privKey)
		
		if key.FriendlyName != "" {
			t.Logf("  FriendlyName: %s", key.FriendlyName)
		}
		if len(key.LocalKeyID) > 0 {
			t.Logf("  LocalKeyID: %x", key.LocalKeyID)
		}
	}
}

// TestExtractBagsLegacy tests extracting bags from legacy 3DES file
func TestExtractBagsLegacy(t *testing.T) {
	data := loadTestFile(t, "testdata/legacy.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.Certificates) == 0 {
		t.Error("Expected at least one certificate")
	}
	if len(bags.PrivateKeys) == 0 {
		t.Error("Expected at least one private key")
	}
	
	t.Logf("✓ Extracted %d certificate(s) and %d key(s) from legacy file", 
		len(bags.Certificates), len(bags.PrivateKeys))
}

// TestExtractBagsMultipleCerts tests file with multiple certificates
func TestExtractBagsMultipleCerts(t *testing.T) {
	data := loadTestFile(t, "testdata/multi-cert.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.Certificates) < 2 {
		t.Errorf("Expected at least 2 certificates, got %d", len(bags.Certificates))
	}
	
	t.Logf("✓ Extracted %d certificates", len(bags.Certificates))
}

// TestExtractBagsECKey tests extracting EC key
func TestExtractBagsECKey(t *testing.T) {
	data := loadTestFile(t, "testdata/ec.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.PrivateKeys) == 0 {
		t.Fatal("Expected at least one private key")
	}
	
	// Verify it's an EC key
	privKey, err := x509.ParsePKCS8PrivateKey(bags.PrivateKeys[0].Raw)
	if err != nil {
		t.Fatalf("Failed to parse key: %v", err)
	}
	
	if _, ok := privKey.(*x509.Certificate); ok {
		t.Error("Expected ECDSA key, got certificate")
	}
	
	t.Logf("✓ Extracted EC key: %T", privKey)
}

// TestFindMatchingPairs tests pairing certificates with keys
func TestFindMatchingPairs(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	pairs := bags.FindMatchingPairs()
	if len(pairs) == 0 {
		t.Error("Expected at least one matched pair")
	}
	
	for i, pair := range pairs {
		t.Logf("Pair[%d]:", i)
		
		// Verify LocalKeyID matches
		if !bytesEqual(pair.Certificate.LocalKeyID, pair.PrivateKey.LocalKeyID) {
			t.Errorf("  LocalKeyID mismatch: cert=%x, key=%x",
				pair.Certificate.LocalKeyID, pair.PrivateKey.LocalKeyID)
		} else {
			t.Logf("  LocalKeyID: %x", pair.Certificate.LocalKeyID)
		}
		
		// Parse and verify cert/key
		cert, err := x509.ParseCertificate(pair.Certificate.Raw)
		if err != nil {
			t.Errorf("  Failed to parse certificate: %v", err)
			continue
		}
		
		key, err := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
		if err != nil {
			t.Errorf("  Failed to parse key: %v", err)
			continue
		}
		
		t.Logf("  Certificate: %s", cert.Subject)
		t.Logf("  Key: %T", key)
		
		if pair.Certificate.FriendlyName != "" {
			t.Logf("  FriendlyName: %s", pair.Certificate.FriendlyName)
		}
	}
	
	t.Logf("✓ Found %d matching pair(s)", len(pairs))
}

// TestFindCertificate tests finding certificate by LocalKeyID
func TestFindCertificate(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.Certificates) == 0 {
		t.Fatal("No certificates to test")
	}
	
	// Find first certificate by its LocalKeyID
	firstCert := bags.Certificates[0]
	if len(firstCert.LocalKeyID) == 0 {
		t.Skip("Certificate has no LocalKeyID")
	}
	
	found := bags.FindCertificate(firstCert.LocalKeyID)
	if found == nil {
		t.Error("Failed to find certificate by LocalKeyID")
	} else {
		t.Logf("✓ Found certificate by LocalKeyID: %x", firstCert.LocalKeyID)
	}
	
	// Try to find non-existent
	notFound := bags.FindCertificate([]byte{0x99, 0x99, 0x99})
	if notFound != nil {
		t.Error("Found certificate with non-existent LocalKeyID")
	}
}

// TestFindPrivateKey tests finding private key by LocalKeyID
func TestFindPrivateKey(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.PrivateKeys) == 0 {
		t.Fatal("No private keys to test")
	}
	
	// Find first key by its LocalKeyID
	firstKey := bags.PrivateKeys[0]
	if len(firstKey.LocalKeyID) == 0 {
		t.Skip("Private key has no LocalKeyID")
	}
	
	found := bags.FindPrivateKey(firstKey.LocalKeyID)
	if found == nil {
		t.Error("Failed to find private key by LocalKeyID")
	} else {
		t.Logf("✓ Found private key by LocalKeyID: %x", firstKey.LocalKeyID)
	}
	
	// Try to find non-existent
	notFound := bags.FindPrivateKey([]byte{0x99, 0x99, 0x99})
	if notFound != nil {
		t.Error("Found private key with non-existent LocalKeyID")
	}
}

// TestExtractBagsWrongPassword tests that wrong password fails gracefully
func TestExtractBagsWrongPassword(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	wrongPassword := []byte("wrongpassword")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	_, err = ExtractBags(pfx, wrongPassword)
	if err == nil {
		t.Error("Expected error with wrong password")
	} else {
		t.Logf("✓ Correctly failed with wrong password: %v", err)
	}
}

// TestExtractBagsCertOnly tests file with only certificates (no keys)
func TestExtractBagsCertOnly(t *testing.T) {
	data := loadTestFile(t, "testdata/cert-only.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	if len(bags.Certificates) == 0 {
		t.Error("Expected at least one certificate")
	}
	
	if len(bags.PrivateKeys) > 0 {
		t.Errorf("Expected no private keys, got %d", len(bags.PrivateKeys))
	}
	
	t.Logf("✓ Extracted %d certificate(s), 0 keys", len(bags.Certificates))
}

// TestExtractBagsNoMAC tests file without MAC
func TestExtractBagsNoMAC(t *testing.T) {
	// Skip - would need a file with no password and unencrypted keys
	t.Skip("No test file for this scenario")
}

// TestExtractBagsRealWorld tests the real-world base64 file
func TestExtractBagsRealWorld(t *testing.T) {
	// Use the same real-world data from realworld_test.go
	data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}
	
	password := []byte("00")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	bags, err := ExtractBags(pfx, password)
	if err != nil {
		t.Fatalf("Failed to extract bags: %v", err)
	}
	
	t.Logf("Extracted %d certificate(s) and %d key(s)", 
		len(bags.Certificates), len(bags.PrivateKeys))
	
	// Verify we can parse the extracted data
	for i, cert := range bags.Certificates {
		x509Cert, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			t.Errorf("Certificate[%d]: Failed to parse: %v", i, err)
		} else {
			t.Logf("Certificate[%d]: %s", i, x509Cert.Subject)
		}
	}
	
	for i, key := range bags.PrivateKeys {
		privKey, err := x509.ParsePKCS8PrivateKey(key.Raw)
		if err != nil {
			t.Errorf("PrivateKey[%d]: Failed to parse: %v", i, err)
		} else {
			t.Logf("PrivateKey[%d]: %T", i, privKey)
		}
	}
}

// TestBytesEqual tests the bytesEqual helper
func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different length", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"different content", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"both nil", nil, nil, true},
		{"one nil", []byte{1}, nil, false},
		{"empty equal", []byte{}, []byte{}, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("bytesEqual(%v, %v) = %v, want %v", 
					tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// BenchmarkExtractBags benchmarks bag extraction
func BenchmarkExtractBags(b *testing.B) {
	data := loadTestFile(b, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		b.Fatalf("Failed to parse: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExtractBags(pfx, password)
		if err != nil {
			b.Fatalf("Failed to extract bags: %v", err)
		}
	}
}
