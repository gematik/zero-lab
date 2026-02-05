package pkcs12

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// TestDecryptModernPKCS12 tests decrypting a modern PKCS#12 file
func TestDecryptModernPKCS12(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Verify MAC first
	if err := VerifyMAC(pfx, password); err != nil {
		t.Fatalf("MAC verification failed: %v", err)
	}
	t.Log("✓ MAC verification passed")
	
	// Parse authenticated safe
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	certCount := 0
	keyCount := 0
	
	// Process each content info
	for i, ci := range authSafe.ContentInfos {
		t.Logf("Processing ContentInfo[%d]: %v", i, ci.ContentType)
		
		var safeContentsData []byte
		
		if ci.ContentType.Equal(OIDEncryptedData) {
			// Decrypt encrypted data
			decrypted, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt ContentInfo[%d]: %v", i, err)
				continue
			}
			safeContentsData = decrypted
			t.Logf("  ✓ Decrypted %d bytes", len(decrypted))
			
		} else if ci.ContentType.Equal(OIDData) {
			// Extract unencrypted data
			var err error
			safeContentsData, err = extractOctetString(ci.Content)
			if err != nil {
				t.Errorf("Failed to extract data: %v", err)
				continue
			}
		}
		
		// Parse safe contents
		sc, err := ParseSafeContents(safeContentsData)
		if err != nil {
			t.Errorf("Failed to parse safe contents: %v", err)
			continue
		}
		
		// Process bags
		for j, bag := range sc.Bags {
			t.Logf("  Bag[%d]: %v", j, bag.BagID)
			
			switch {
			case bag.BagID.Equal(OIDCertBag):
				certCount++
				certBag, err := ParseCertBag(bag.BagValue)
				if err != nil {
					t.Errorf("Failed to parse cert bag: %v", err)
					continue
				}
				
				if certBag.CertID.Equal(OIDX509Certificate) {
					cert, err := x509.ParseCertificate(certBag.CertValue)
					if err != nil {
						t.Errorf("Failed to parse certificate: %v", err)
					} else {
						t.Logf("    ✓ Certificate: %s", cert.Subject)
						
						if name, ok := GetFriendlyName(bag.Attributes); ok {
							t.Logf("    Friendly name: %s", name)
						}
					}
				}
				
			case bag.BagID.Equal(OIDPKCS8ShroudedKeyBag):
				keyCount++
				
				// Decrypt the key
				pkcs8Data, err := DecryptShroudedKeyBag(bag.BagValue, password)
				if err != nil {
					t.Errorf("Failed to decrypt key: %v", err)
					continue
				}
				
				t.Logf("    ✓ Decrypted key: %d bytes", len(pkcs8Data))
				
				// Parse the private key
				privateKey, err := x509.ParsePKCS8PrivateKey(pkcs8Data)
				if err != nil {
					t.Errorf("Failed to parse private key: %v", err)
				} else {
					t.Logf("    ✓ Private key type: %T", privateKey)
				}
			}
		}
	}
	
	t.Logf("\nSummary:")
	t.Logf("  Certificates: %d", certCount)
	t.Logf("  Private keys: %d", keyCount)
	
	if certCount == 0 {
		t.Error("Expected at least one certificate")
	}
	if keyCount == 0 {
		t.Error("Expected at least one private key")
	}
}

// TestDecryptRealWorldPKCS12 tests decrypting the real-world PKCS#12 file
func TestDecryptRealWorldPKCS12(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}
	
	password := []byte(testPFXPassword)
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Verify MAC
	if err := VerifyMAC(pfx, password); err != nil {
		t.Fatalf("MAC verification failed: %v", err)
	}
	t.Log("✓ MAC verification passed")
	
	// Parse authenticated safe
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	certCount := 0
	keyCount := 0
	
	for i, ci := range authSafe.ContentInfos {
		var safeContentsData []byte
		
		if ci.ContentType.Equal(OIDEncryptedData) {
			decrypted, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt: %v", err)
				continue
			}
			safeContentsData = decrypted
			t.Logf("ContentInfo[%d]: Decrypted %d bytes", i, len(decrypted))
			
		} else if ci.ContentType.Equal(OIDData) {
			safeContentsData, err = extractOctetString(ci.Content)
			if err != nil {
				t.Logf("ContentInfo[%d]: Failed to extract: %v", i, err)
				continue
			}
		}
		
		sc, err := ParseSafeContents(safeContentsData)
		if err != nil {
			t.Logf("ContentInfo[%d]: Failed to parse safe contents: %v", i, err)
			continue
		}
		
		for _, bag := range sc.Bags {
			if bag.BagID.Equal(OIDCertBag) {
				certCount++
				certBag, _ := ParseCertBag(bag.BagValue)
				if certBag != nil && certBag.CertID.Equal(OIDX509Certificate) {
					cert, err := x509.ParseCertificate(certBag.CertValue)
					if err == nil {
						t.Logf("  ✓ Certificate: %s", cert.Subject)
					}
				}
			} else if bag.BagID.Equal(OIDPKCS8ShroudedKeyBag) {
				keyCount++
				pkcs8Data, err := DecryptShroudedKeyBag(bag.BagValue, password)
				if err == nil {
					t.Logf("  ✓ Decrypted private key: %d bytes", len(pkcs8Data))
					if key, err := x509.ParsePKCS8PrivateKey(pkcs8Data); err == nil {
						t.Logf("    Key type: %T", key)
					}
				}
			}
		}
	}
	
	t.Logf("\nReal-world file summary:")
	t.Logf("  Certificates: %d", certCount)
	t.Logf("  Private keys: %d", keyCount)
}

// TestDecryptLegacy3DES tests decrypting legacy 3DES file
func TestDecryptLegacy3DES(t *testing.T) {
	data := loadTestFile(t, "testdata/legacy.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Verify MAC (should be SHA-1 for legacy)
	if err := VerifyMAC(pfx, password); err != nil {
		t.Fatalf("MAC verification failed: %v", err)
	}
	t.Log("✓ MAC verification passed (legacy)")
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	decryptedCount := 0
	
	for i, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			decrypted, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt legacy content: %v", err)
				continue
			}
			decryptedCount++
			t.Logf("ContentInfo[%d]: Decrypted %d bytes (3DES)", i, len(decrypted))
		}
	}
	
	if decryptedCount == 0 {
		t.Error("Expected to decrypt at least one encrypted content")
	}
}

// TestDecryptEmptyPassword tests decryption with empty password
func TestDecryptEmptyPassword(t *testing.T) {
	data := loadTestFile(t, "testdata/empty-pass.p12")
	password := []byte("") // Empty password
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Verify MAC with empty password
	if err := VerifyMAC(pfx, password); err != nil {
		t.Fatalf("MAC verification failed with empty password: %v", err)
	}
	t.Log("✓ MAC verification passed with empty password")
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			_, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt with empty password: %v", err)
			} else {
				t.Log("✓ Successfully decrypted with empty password")
			}
		}
	}
}

// TestMACVerificationWrongPassword tests MAC verification with wrong password
func TestMACVerificationWrongPassword(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	wrongPassword := []byte("wrongpassword")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Should fail with wrong password
	err = VerifyMAC(pfx, wrongPassword)
	if err == nil {
		t.Error("Expected MAC verification to fail with wrong password")
	} else if err != ErrAuthentication {
		t.Errorf("Expected ErrAuthentication, got: %v", err)
	} else {
		t.Logf("✓ Correctly rejected wrong password: %v", err)
	}
}

// TestDecryptionWrongPassword tests decryption with wrong password
func TestDecryptionWrongPassword(t *testing.T) {
	data := loadTestFile(t, "testdata/modern.p12")
	wrongPassword := []byte("wrongpassword")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			_, err := DecryptEncryptedData(ci, wrongPassword)
			// Should fail - either during decryption or padding removal
			if err == nil {
				t.Error("Expected decryption to fail with wrong password")
			} else {
				t.Logf("✓ Correctly failed with wrong password: %v", err)
			}
			break
		}
	}
}

// TestPKCS7PaddingRemoval tests PKCS#7 padding removal
func TestPKCS7PaddingRemoval(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid padding 1 byte",
			input:   []byte{1, 2, 3, 4, 5, 1},
			want:    []byte{1, 2, 3, 4, 5},
			wantErr: false,
		},
		{
			name:    "valid padding 4 bytes",
			input:   []byte{1, 2, 3, 4, 4, 4, 4, 4},
			want:    []byte{1, 2, 3, 4},
			wantErr: false,
		},
		{
			name:    "valid padding full block",
			input:   []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "invalid padding - zero",
			input:   []byte{1, 2, 3, 0},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid padding - wrong value",
			input:   []byte{1, 2, 3, 4, 3},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := removePKCS7Padding(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("removePKCS7Padding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("removePKCS7Padding() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPasswordEncoding tests PKCS#12 password encoding
func TestPasswordEncoding(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		want     []byte
	}{
		{
			name:     "empty password",
			password: []byte(""),
			want:     []byte{0, 0},
		},
		{
			name:     "ASCII password",
			password: []byte("test"),
			want:     []byte{0, 't', 0, 'e', 0, 's', 0, 't', 0, 0},
		},
		{
			name:     "numeric password",
			password: []byte("123"),
			want:     []byte{0, '1', 0, '2', 0, '3', 0, 0},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodePasswordPKCS12(tt.password)
			if string(got) != string(tt.want) {
				t.Errorf("encodePasswordPKCS12() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecryptAES128 tests AES-128 decryption
func TestDecryptAES128(t *testing.T) {
	data := loadTestFile(t, "testdata/aes128.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	if err := VerifyMAC(pfx, password); err != nil {
		t.Fatalf("MAC verification failed: %v", err)
	}
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	decrypted := false
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			_, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt AES-128: %v", err)
			} else {
				decrypted = true
				t.Log("✓ Successfully decrypted AES-128 content")
			}
		}
	}
	
	if !decrypted {
		t.Error("Expected to decrypt at least one AES-128 encrypted content")
	}
}

// TestDecryptNoMAC tests decryption of file without MAC
func TestDecryptNoMAC(t *testing.T) {
	data := loadTestFile(t, "testdata/no-mac.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	
	// Should not fail with no MAC
	if err := VerifyMAC(pfx, password); err != nil {
		t.Errorf("MAC verification should not fail when no MAC present: %v", err)
	}
	t.Log("✓ No MAC verification (file has no MAC)")
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			_, err := DecryptEncryptedData(ci, password)
			if err != nil {
				t.Errorf("Failed to decrypt: %v", err)
			}
		}
	}
}

// BenchmarkDecryptPBES2 benchmarks PBES2 decryption
func BenchmarkDecryptPBES2(b *testing.B) {
	data := loadTestFile(b, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		b.Fatalf("Failed to parse: %v", err)
	}
	
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		b.Fatalf("Failed to parse authenticated safe: %v", err)
	}
	
	var encryptedCI ContentInfo
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(OIDEncryptedData) {
			encryptedCI = ci
			break
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptEncryptedData(encryptedCI, password)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkVerifyMAC benchmarks MAC verification
func BenchmarkVerifyMAC(b *testing.B) {
	data := loadTestFile(b, "testdata/modern.p12")
	password := []byte("test1234")
	
	pfx, err := Parse(data)
	if err != nil {
		b.Fatalf("Failed to parse: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := VerifyMAC(pfx, password)
		if err != nil {
			b.Fatalf("MAC verification failed: %v", err)
		}
	}
}
