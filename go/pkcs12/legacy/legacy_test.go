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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/internal/conformance"
)

// TestConformance decodes every case of the spec/pkcs12 corpus.
func TestConformance(t *testing.T) {
	for _, c := range conformance.Corpus(t) {
		t.Run(c.ID+"/"+c.Encoding, func(t *testing.T) {
			bags, err := Decode(c.Data, c.Password)
			conformance.Check(t, c, bags, err)
		})
	}
}

func vendorFile(t testing.TB, name string) (data, password []byte) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "spec", "pkcs12", "testdata", "vendor")
	data, err := os.ReadFile(filepath.Join(dir, name+".p12"))
	if err != nil {
		t.Fatal(err)
	}
	password, err = os.ReadFile(filepath.Join(dir, name+"-password.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return data, bytes.TrimRight(password, "\r\n")
}

// TestVendorFiles reads the two connector client identities without OpenSSL;
// it runs where the corpus cannot be generated.
func TestVendorFiles(t *testing.T) {
	tests := []struct {
		name     string
		certs    int
		leafName string
		leafSHA  string
	}{
		{"cgm", 2, "test-cs2", "0933a917958c818107528d747fe480c5fc9b92556bdb46a0295aca3f5d5aa944"},
		{"secunet", 1, "valid_ec", "ea5011332622957771eb448cfba188951d59f8fdc9b39bf4bd242b3c4f153341"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, password := vendorFile(t, tt.name)
			if !IsBER(data) {
				t.Fatal("vendor file is expected to be BER")
			}
			if _, err := pkcs12.Decode(data, password); !errors.Is(err, pkcs12.ErrInvalidPFX) {
				t.Errorf("pkcs12.Decode error = %v, want ErrInvalidPFX", err)
			}

			bags, err := Decode(data, password)
			if err != nil {
				t.Fatal(err)
			}
			if len(bags.Certificates) != tt.certs || len(bags.PrivateKeys) != 1 {
				t.Fatalf("%d certificates and %d keys, want %d and 1", len(bags.Certificates), len(bags.PrivateKeys), tt.certs)
			}
			pairs := bags.FindMatchingPairs()
			if len(pairs) != 1 {
				t.Fatalf("%d pairs, want 1", len(pairs))
			}
			sum := sha256.Sum256(pairs[0].Certificate.Raw)
			if got := hex.EncodeToString(sum[:]); got != tt.leafSHA {
				t.Errorf("paired certificate %s, want %s", got, tt.leafSHA)
			}
			if pairs[0].Certificate.FriendlyName != tt.leafName || pairs[0].PrivateKey.FriendlyName != tt.leafName {
				t.Errorf("friendly names %q/%q, want %q", pairs[0].Certificate.FriendlyName, pairs[0].PrivateKey.FriendlyName, tt.leafName)
			}

			if _, err := Decode(data, []byte("wrong")); !errors.Is(err, pkcs12.ErrAuthentication) {
				t.Errorf("wrong password: error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestConvertWithOpenSSL(t *testing.T) {
	data, password := vendorFile(t, "secunet")
	modern, err := ConvertWithOpenSSL(data, string(password))
	if err != nil {
		t.Fatal(err)
	}
	if IsBER(modern) {
		t.Error("converted file is BER")
	}
	want, err := Decode(data, password)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pkcs12.Decode(modern, password)
	if err != nil {
		t.Fatalf("pkcs12.Decode of the converted file: %v", err)
	}
	if !bytes.Equal(got.Certificates[0].Raw, want.Certificates[0].Raw) || !bytes.Equal(got.PrivateKeys[0].Raw, want.PrivateKeys[0].Raw) {
		t.Error("converted file holds other contents")
	}
}

func TestIsBER(t *testing.T) {
	for _, tt := range []struct {
		data []byte
		want bool
	}{
		{[]byte{0x30, 0x80, 0x01}, true},
		{[]byte{0x30, 0x10, 0x01}, false},
		{[]byte{0x30}, false},
		{nil, false},
	} {
		if got := IsBER(tt.data); got != tt.want {
			t.Errorf("IsBER(% x) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

// TestEncryptedContentSegments covers the constructed form of
// encryptedContent, which only the schema can join.
func TestEncryptedContentSegments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"primitive", "80 03 01 02 03", "01 02 03"},
		{"constructed", "A0 08 04 02 01 02 04 02 03 04", "01 02 03 04"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := unhex(t, tt.in)
			s := cryptobyteString(in)
			got, err := encryptedContent(&s)
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, tt.want); !bytes.Equal(got, want) {
				t.Errorf("got % x, want % x", got, want)
			}
		})
	}
	s := cryptobyteString(unhex(t, "A0 03 0C 01 41"))
	if _, err := encryptedContent(&s); !errors.Is(err, pkcs12.ErrParse) {
		t.Errorf("segment of another type: error = %v, want ErrParse", err)
	}
}

func FuzzDecode(f *testing.F) {
	data, password := vendorFile(f, "secunet")
	f.Add(data, password)
	f.Fuzz(func(t *testing.T, data, password []byte) {
		bags, err := Decode(data, password)
		if err == nil && bags == nil {
			t.Fatal("nil Bags without error")
		}
	})
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cryptobyteString(b []byte) cryptobyte.String { return cryptobyte.String(b) }

func ExampleDecode() {
	data, err := os.ReadFile("../../../spec/pkcs12/testdata/vendor/secunet.p12")
	if err != nil {
		log.Fatal(err)
	}
	password, err := os.ReadFile("../../../spec/pkcs12/testdata/vendor/secunet-password.txt")
	if err != nil {
		log.Fatal(err)
	}
	// legacy.Decode reads BER and RC2 as well as everything pkcs12.Decode reads.
	bags, err := Decode(data, bytes.TrimSpace(password))
	if err != nil {
		log.Fatal(err)
	}
	for _, pair := range bags.FindMatchingPairs() {
		fmt.Println(pair.Certificate.FriendlyName)
	}
	// Output: valid_ec
}
