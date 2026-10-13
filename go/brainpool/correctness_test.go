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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A certificate whose subject public key does not decode to a point on the
// curve must be an error, not a certificate carrying a nil-coordinate key.
func TestParseCertificate_RejectsInvalidPublicKeyPoint(t *testing.T) {
	block, _ := pem.Decode(testCertBytes)
	der := append([]byte(nil), block.Bytes...)
	cert, err := brainpool.ParseCertificate(der)
	require.NoError(t, err)

	// The SPKI ends with the uncompressed point 0x04‖X‖Y; corrupt the last
	// byte of Y so (X, Y) is no longer on the curve.
	spki := cert.RawSubjectPublicKeyInfo
	require.Equal(t, byte(0x04), spki[len(spki)-64-1])
	tampered := append([]byte(nil), der...)
	off := indexOf(der, spki)
	require.GreaterOrEqual(t, off, 0)
	tampered[off+len(spki)-1] ^= 0x01

	_, err = brainpool.ParseCertificate(tampered)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on brainpoolP256r1")
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func TestParsePrivateKeyPEM_NonECPKCS8IsAnError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	key, err := brainpool.ParsePrivateKeyPEM(pemBytes)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "not an ECDSA key")
}

// The public key is recomputed from d; it must agree with the point the SEC1
// structure carries, and with the big.Int oracle.
func TestParseECPrivateKey_PublicKeyMatchesEmbedded(t *testing.T) {
	block, _ := pem.Decode(testKeyBytes)
	key, err := brainpool.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	var sec1 struct {
		Version    int
		PrivateKey []byte
		NamedCurve asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	_, err = asn1.Unmarshal(block.Bytes, &sec1)
	require.NoError(t, err)
	pub := sec1.PublicKey.RightAlign()
	require.Len(t, pub, 65)
	assert.Equal(t, 0, key.X.Cmp(new(big.Int).SetBytes(pub[1:33])))
	assert.Equal(t, 0, key.Y.Cmp(new(big.Int).SetBytes(pub[33:])))

	ox, oy := brainpool.P256r1().ScalarBaseMult(key.D.Bytes())
	assert.Equal(t, 0, key.X.Cmp(ox))
	assert.Equal(t, 0, key.Y.Cmp(oy))
}

func TestGenerateKey(t *testing.T) {
	for _, curve := range []elliptic.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1(), elliptic.P256()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := brainpool.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			assert.Equal(t, curve, key.Curve)
			assert.Equal(t, 1, key.D.Sign())
			assert.Less(t, key.D.Cmp(curve.Params().N), 0)
			assert.True(t, curve.IsOnCurve(key.X, key.Y))

			h := sha256.Sum256([]byte("generated key signs"))
			sig, err := brainpool.SignFuncPrivateKey(key)(h[:])
			require.NoError(t, err)
			n := (curve.Params().BitSize + 7) / 8
			r := new(big.Int).SetBytes(sig[:n])
			s := new(big.Int).SetBytes(sig[n:])
			assert.True(t, ecdsa.Verify(&key.PublicKey, h[:], r, s))
		})
	}
}
