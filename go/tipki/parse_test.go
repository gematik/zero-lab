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

package tipki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

const pkiFixtures = "../../rust/ti-pki/tests/pki/"

func fixtureDER(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(pkiFixtures + name)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	return block.Bytes
}

func TestParseCertificateTakesTheKeysOfTheTI(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{
		"sub-ca-hba.pem":  brainpool.P256r1(),
		"sub-ca-komp.pem": elliptic.P256(),
	} {
		cert, err := ParseCertificate(fixtureDER(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != curve {
			t.Errorf("%s: %T", name, cert.PublicKey)
		}
	}
}

// Parsing grants no trust: a key the trust path refuses still parses, for a caller only reading it.
func TestParseCertificateTakesWhatThePathRefuses(t *testing.T) {
	rsa, err := ParseCertificate(fixtureDER(t, "rca-rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if rsa.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("%v", rsa.PublicKeyAlgorithm)
	}
	if _, err := ParseCertificate(fixtureDER(t, "ee-p521.pem")); err != nil {
		t.Error(err)
	}
}

func TestParseCertificateRefusesWhatIsNoCertificate(t *testing.T) {
	if _, err := ParseCertificate([]byte("no certificate")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestParsePEMCertificatesSkipsOtherBlocks(t *testing.T) {
	cert := func(name string) []byte {
		body, err := os.ReadFile(pkiFixtures + name)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})
	data := append(append(cert("rca1.pem"), key...), cert("sub-ca-hba.pem")...)
	certs, err := ParsePEMCertificates(data)
	if err != nil || len(certs) != 2 {
		t.Fatalf("%d %v", len(certs), err)
	}
	if none, err := ParsePEMCertificates([]byte("nothing here")); err != nil || len(none) != 0 {
		t.Errorf("%v %v", none, err)
	}
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	if _, err := ParsePEMCertificates(broken); err == nil {
		t.Error("a broken certificate block")
	}
}

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := ParseCertificate(der)
		if (cert == nil) != (err != nil) {
			t.Errorf("%v %v", cert, err)
		}
	})
}
