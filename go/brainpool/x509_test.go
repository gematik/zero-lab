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

package brainpool_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// The Raw* fields must be the original encoding, not the copy with the
// swapped algorithm OID: signature checks hash RawTBSCertificate and OCSP
// request builders re-parse RawSubjectPublicKeyInfo.
func TestParseCertificate_RawFieldsAreOriginalBytes(t *testing.T) {
	block, _ := pem.Decode(testCertBytes)
	cert, err := brainpool.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cert.Raw, block.Bytes) {
		t.Error("Raw is not the original DER")
	}
	for name, raw := range map[string][]byte{
		"RawTBSCertificate":       cert.RawTBSCertificate,
		"RawSubjectPublicKeyInfo": cert.RawSubjectPublicKeyInfo,
		"RawSubject":              cert.RawSubject,
		"RawIssuer":               cert.RawIssuer,
	} {
		if !bytes.Contains(block.Bytes, raw) {
			t.Errorf("%s is not a slice of the original DER", name)
		}
	}
	// The swapped OID never leaks: the SPKI still names id-ecPublicKey.
	if !bytes.Contains(cert.RawSubjectPublicKeyInfo, []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}) {
		t.Error("RawSubjectPublicKeyInfo does not name id-ecPublicKey")
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSA-SHA256", cert.SignatureAlgorithm)
	}
}

// Extensions the hand-written parser never decoded now come from crypto/x509.
func TestParseCertificate_DecodesEveryExtension(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testCertBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.CRLDistributionPoints, []string{"http://ehca.gematik.de/crl/"}) {
		t.Errorf("CRLDistributionPoints = %v", cert.CRLDistributionPoints)
	}
	if !slices.Equal(cert.OCSPServer, []string{"http://ehca.gematik.de/ecc-ocsp"}) {
		t.Errorf("OCSPServer = %v", cert.OCSPServer)
	}
	if len(cert.Policies) != 2 {
		t.Errorf("%d policies, want 2", len(cert.Policies))
	}
	if cert.Version != 3 {
		t.Errorf("Version = %d, want 3", cert.Version)
	}
}

// A Brainpool-signed chain verifies through the standard library's own
// CheckSignatureFrom, which still has a big.Int path for custom curves.
func TestParseCertificate_ChainVerifiesWithStdlib(t *testing.T) {
	var chain [3]*x509.Certificate
	for i, pemBytes := range [][]byte{testCertBytes, testCaCertBytes, testRootCaCertBytes} {
		cert, err := brainpool.ParseCertificatePEM(pemBytes)
		if err != nil {
			t.Fatal(err)
		}
		chain[i] = cert
	}
	leaf, ca, root := chain[0], chain[1], chain[2]

	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Errorf("leaf from CA: %v", err)
	}
	if err := ca.CheckSignatureFrom(root); err != nil {
		t.Errorf("CA from root: %v", err)
	}
	if leaf.CheckSignatureFrom(root) == nil {
		t.Error("leaf is not signed by the root, but its signature verified")
	}
}

// Certificates on other curves take the plain crypto/x509 path unchanged.
func TestParseCertificate_NonBrainpoolFallsThrough(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nist"},
		DNSNames:     []string{"nist.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.DNSNames, []string{"nist.example"}) {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("PublicKey = %T, want a P-256 *ecdsa.PublicKey", cert.PublicKey)
	}
}

func TestValidatePublicKey(t *testing.T) {
	key, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := brainpool.ValidatePublicKey(&key.PublicKey); err != nil {
		t.Fatalf("generated key: %v", err)
	}

	p := brainpool.P256r1().Params().P
	for name, pub := range map[string]*ecdsa.PublicKey{
		"nil":          nil,
		"nil coords":   {Curve: brainpool.P256r1()},
		"off curve":    {Curve: brainpool.P256r1(), X: key.X, Y: new(big.Int).Add(key.Y, big.NewInt(1))},
		"out of range": {Curve: brainpool.P256r1(), X: new(big.Int).Add(key.X, p), Y: key.Y},
	} {
		if brainpool.ValidatePublicKey(pub) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
