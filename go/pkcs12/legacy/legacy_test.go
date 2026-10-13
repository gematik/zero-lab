// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package legacy

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/pkcs12"
)

func loadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	return data
}

func loadPassword(t *testing.T, filename string) string {
	t.Helper()
	data := loadFile(t, filename)
	return strings.TrimSpace(string(data))
}

func TestIsBER(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "BER indefinite length",
			data: []byte{0x30, 0x80, 0x01, 0x02},
			want: true,
		},
		{
			name: "DER definite length",
			data: []byte{0x30, 0x10, 0x01, 0x02},
			want: false,
		},
		{
			name: "too short",
			data: []byte{0x30},
			want: false,
		},
		{
			name: "empty",
			data: []byte{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBER(tt.data)
			if got != tt.want {
				t.Errorf("IsBER() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertWithOpenSSL_CGM(t *testing.T) {
	berData := loadFile(t, "cgm.p12")
	password := loadPassword(t, "cgm-password.txt")

	if !IsBER(berData) {
		t.Skip("cgm.p12 is not BER encoded")
	}

	derData, err := ConvertWithOpenSSL(berData, password)
	if err != nil {
		t.Fatalf("ConvertWithOpenSSL failed: %v", err)
	}

	if len(derData) == 0 {
		t.Fatal("converted data is empty")
	}

	pfx, err := pkcs12.Parse(derData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	bags, err := pkcs12.ExtractBags(pfx, []byte(password))
	if err != nil {
		t.Fatalf("ExtractBags failed: %v", err)
	}

	if len(bags.Certificates) == 0 {
		t.Error("no certificates found")
	}

	t.Logf("Certificates: %d", len(bags.Certificates))
	for i, certBag := range bags.Certificates {
		cert, err := x509.ParseCertificate(certBag.Raw)
		if err != nil {
			t.Logf("  Certificate %d: parse error: %v", i, err)
			continue
		}
		t.Logf("  Certificate %d: %s", i, cert.Subject.CommonName)
	}

	t.Logf("Keys: %d", len(bags.PrivateKeys))
	t.Logf("Pairs: %d", len(bags.FindMatchingPairs()))
}

func TestConvertWithOpenSSL_Secunet(t *testing.T) {
	berData := loadFile(t, "secunet.p12")
	password := loadPassword(t, "secunet-password.txt")

	if !IsBER(berData) {
		t.Skip("secunet.p12 is not BER encoded")
	}

	derData, err := ConvertWithOpenSSL(berData, password)
	if err != nil {
		t.Fatalf("ConvertWithOpenSSL failed: %v", err)
	}

	if len(derData) == 0 {
		t.Fatal("converted data is empty")
	}

	pfx, err := pkcs12.Parse(derData)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	bags, err := pkcs12.ExtractBags(pfx, []byte(password))
	if err != nil {
		t.Fatalf("ExtractBags failed: %v", err)
	}

	if len(bags.Certificates) == 0 {
		t.Error("no certificates found")
	}

	t.Logf("Certificates: %d", len(bags.Certificates))
	for i, certBag := range bags.Certificates {
		cert, err := x509.ParseCertificate(certBag.Raw)
		if err != nil {
			t.Logf("  Certificate %d: parse error: %v", i, err)
			continue
		}
		t.Logf("  Certificate %d: %s", i, cert.Subject.CommonName)
	}

	t.Logf("Keys: %d", len(bags.PrivateKeys))
	t.Logf("Pairs: %d", len(bags.FindMatchingPairs()))
}
