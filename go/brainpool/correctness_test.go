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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// A certificate whose subject public key does not decode to a point on the
// curve must be an error, not a certificate carrying a nil-coordinate key.
func TestParseCertificate_RejectsInvalidPublicKeyPoint(t *testing.T) {
	block, _ := pem.Decode(testCertBytes)
	der := append([]byte(nil), block.Bytes...)
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// The SPKI ends with the uncompressed point 0x04‖X‖Y; corrupt the last
	// byte of Y so (X, Y) is no longer on the curve.
	spki := cert.RawSubjectPublicKeyInfo
	if len(spki) < 65 || spki[len(spki)-64-1] != 0x04 {
		t.Fatalf("SPKI does not end with an uncompressed P-256 point: %X", spki)
	}
	tampered := append([]byte(nil), der...)
	off := bytes.Index(der, spki)
	if off < 0 {
		t.Fatal("RawSubjectPublicKeyInfo is not a slice of the DER")
	}
	tampered[off+len(spki)-1] ^= 0x01

	_, err = brainpool.ParseCertificate(tampered)
	if err == nil || !strings.Contains(err.Error(), "not on brainpoolP256r1") {
		t.Fatalf("ParseCertificate(tampered) = %v, want an error about a point not on brainpoolP256r1", err)
	}
}

func TestParsePrivateKeyPEM_NonECPKCS8IsAnError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	key, err := brainpool.ParsePrivateKeyPEM(pemBytes)
	if err == nil || !strings.Contains(err.Error(), "not an ECDSA key") {
		t.Fatalf("ParsePrivateKeyPEM(Ed25519) error = %v, want \"not an ECDSA key\"", err)
	}
	if key != nil {
		t.Error("ParsePrivateKeyPEM returned a key along with the error")
	}
}

// The public key is recomputed from d; it must agree with the point the SEC1
// structure carries, and with the big.Int oracle.
func TestParseECPrivateKey_PublicKeyMatchesEmbedded(t *testing.T) {
	block, _ := pem.Decode(testKeyBytes)
	key, err := brainpool.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	var sec1 struct {
		Version    int
		PrivateKey []byte
		NamedCurve asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(block.Bytes, &sec1); err != nil {
		t.Fatal(err)
	}
	pub := sec1.PublicKey.RightAlign()
	if len(pub) != 65 {
		t.Fatalf("embedded public key is %d bytes, want 65", len(pub))
	}
	if key.X.Cmp(new(big.Int).SetBytes(pub[1:33])) != 0 || key.Y.Cmp(new(big.Int).SetBytes(pub[33:])) != 0 {
		t.Error("recomputed public key differs from the embedded one")
	}

	ox, oy := brainpool.P256r1().ScalarBaseMult(key.D.Bytes())
	if key.X.Cmp(ox) != 0 || key.Y.Cmp(oy) != 0 {
		t.Error("recomputed public key differs from the big.Int oracle")
	}
}

func TestGenerateKey(t *testing.T) {
	for _, curve := range []elliptic.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1(), elliptic.P256()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := brainpool.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if key.Curve != curve {
				t.Errorf("key.Curve = %s, want %s", key.Curve.Params().Name, curve.Params().Name)
			}
			if key.D.Sign() != 1 || key.D.Cmp(curve.Params().N) >= 0 {
				t.Error("d is not in [1, n-1]")
			}
			if !curve.IsOnCurve(key.X, key.Y) {
				t.Error("public key is not on the curve")
			}

			h := sha256.Sum256([]byte("generated key signs"))
			sig, err := brainpool.SignFuncPrivateKey(key)(h[:])
			if err != nil {
				t.Fatal(err)
			}
			n := (curve.Params().BitSize + 7) / 8
			if len(sig) != 2*n {
				t.Fatalf("signature is %d bytes, want %d", len(sig), 2*n)
			}
			r := new(big.Int).SetBytes(sig[:n])
			s := new(big.Int).SetBytes(sig[n:])
			if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
				t.Error("signature does not verify")
			}
		})
	}
}
