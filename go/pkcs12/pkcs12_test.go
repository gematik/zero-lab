package pkcs12

import (
	"encoding/asn1"
	"strings"
	"testing"
)

func TestOIDConstants(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{"Data", OIDData, "1.2.840.113549.1.7.1"},
		{"EncryptedData", OIDEncryptedData, "1.2.840.113549.1.7.6"},
		{"CertBag", OIDCertBag, "1.2.840.113549.1.12.10.1.3"},
		{"PKCS8ShroudedKeyBag", OIDPKCS8ShroudedKeyBag, "1.2.840.113549.1.12.10.1.2"},
		{"X509Certificate", OIDX509Certificate, "1.2.840.113549.1.9.22.1"},
		{"FriendlyName", OIDFriendlyName, "1.2.840.113549.1.9.20"},
		{"LocalKeyID", OIDLocalKeyID, "1.2.840.113549.1.9.21"},
		{"PBES2", OIDPBES2, "1.2.840.113549.1.5.13"},
		{"PBKDF2", OIDPBKDF2, "1.2.840.113549.1.5.12"},
		{"AES128CBC", OIDAes128CBC, "2.16.840.1.101.3.4.1.2"},
		{"AES256CBC", OIDAes256CBC, "2.16.840.1.101.3.4.1.42"},
		{"HMACSHA256", OIDHMACSHA256, "1.2.840.113549.2.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.oid.String() != tt.expected {
				t.Errorf("OID mismatch: got %s, want %s", tt.oid.String(), tt.expected)
			}
		})
	}
}

func TestDecodeBMPString(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    string
		wantErr bool
	}{
		{
			name:  "ASCII text",
			input: []byte{0x00, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f}, // "Hello"
			want:  "Hello",
		},
		{
			name:  "empty string",
			input: []byte{},
			want:  "",
		},
		{
			name:    "odd length",
			input:   []byte{0x00, 0x48, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeBMPString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeBMPString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("decodeBMPString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractOctetString(t *testing.T) {
	// Simple OCTET STRING: 04 05 48 65 6c 6c 6f (contains "Hello")
	data := []byte{0x04, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}

	result, err := extractOctetString(data)
	if err != nil {
		t.Fatalf("extractOctetString() error = %v", err)
	}

	expected := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	if string(result) != string(expected) {
		t.Errorf("extractOctetString() = %v, want %v", result, expected)
	}
}

func TestParseInvalidPFX(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "invalid sequence",
			data: []byte{0x30, 0x00},
		},
		{
			name: "not a sequence",
			data: []byte{0x04, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}

// TestOIDEquality verifies OID comparison works correctly
func TestOIDEquality(t *testing.T) {
	oid1 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oid2 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oid3 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	if !oid1.Equal(oid2) {
		t.Error("Equal OIDs should be equal")
	}

	if oid1.Equal(oid3) {
		t.Error("Different OIDs should not be equal")
	}

	if !OIDData.Equal(oid1) {
		t.Error("OIDData should equal 1.2.840.113549.1.7.1")
	}
}

func TestParseBERIndefiniteLength(t *testing.T) {
	// BER indefinite-length encoding: 0x30 0x80 (SEQUENCE with indefinite length)
	// This should now be automatically converted if valid, or fail with conversion error
	berData := []byte{0x30, 0x80, 0x02, 0x01, 0x03, 0x30, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00}

	_, err := Parse(berData)
	if err == nil {
		t.Fatal("Expected error for incomplete BER structure")
	}

	// Should fail during conversion (missing EOC marker)
	if !strings.Contains(err.Error(), "BER to DER") || !strings.Contains(err.Error(), "EOC") {
		t.Errorf("Error should mention BER-to-DER conversion failure, got: %v", err)
	}

	if !strings.Contains(err.Error(), "openssl") {
		t.Errorf("Error should provide conversion solution, got: %v", err)
	}
}

func TestParseInvalidTag(t *testing.T) {
// Invalid first byte (not SEQUENCE), but large enough
invalidData := []byte{0xFF, 0x10, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

_, err := Parse(invalidData)
if err == nil {
t.Fatal("Expected error for invalid tag")
}

if !strings.Contains(err.Error(), "0xff") || !strings.Contains(err.Error(), "0x30") {
t.Errorf("Error should mention expected and actual tags, got: %v", err)
}
}

func TestParseTooSmall(t *testing.T) {
_, err := Parse([]byte{0x30, 0x05})
if err == nil {
t.Fatal("Expected error for file too small")
}

if !strings.Contains(err.Error(), "too small") {
t.Errorf("Error should mention file is too small, got: %v", err)
}
}
