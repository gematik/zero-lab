package brainpool_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Raw* fields must be the original encoding, not the copy with the
// swapped algorithm OID: signature checks hash RawTBSCertificate and OCSP
// request builders re-parse RawSubjectPublicKeyInfo.
func TestParseCertificate_RawFieldsAreOriginalBytes(t *testing.T) {
	block, _ := pem.Decode(testCertBytes)
	cert, err := brainpool.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, block.Bytes, cert.Raw)
	for name, raw := range map[string][]byte{
		"RawTBSCertificate":       cert.RawTBSCertificate,
		"RawSubjectPublicKeyInfo": cert.RawSubjectPublicKeyInfo,
		"RawSubject":              cert.RawSubject,
		"RawIssuer":               cert.RawIssuer,
	} {
		assert.True(t, contains(block.Bytes, raw), "%s is not a slice of the original DER", name)
	}
	// The swapped OID never leaks: the SPKI still names id-ecPublicKey.
	assert.Contains(t, string(cert.RawSubjectPublicKeyInfo), string([]byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}))
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func contains(haystack, needle []byte) bool { return indexOf(haystack, needle) >= 0 }

// Extensions the hand-written parser never decoded now come from crypto/x509.
func TestParseCertificate_DecodesEveryExtension(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testCertBytes)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://ehca.gematik.de/crl/"}, cert.CRLDistributionPoints)
	assert.Equal(t, []string{"http://ehca.gematik.de/ecc-ocsp"}, cert.OCSPServer)
	assert.Len(t, cert.Policies, 2)
	assert.Equal(t, 3, cert.Version)
}

// A Brainpool-signed chain verifies through the standard library's own
// CheckSignatureFrom, which still has a big.Int path for custom curves.
func TestParseCertificate_ChainVerifiesWithStdlib(t *testing.T) {
	leaf, err := brainpool.ParseCertificatePEM(testCertBytes)
	require.NoError(t, err)
	ca, err := brainpool.ParseCertificatePEM(testCaCertBytes)
	require.NoError(t, err)
	root, err := brainpool.ParseCertificatePEM(testRootCaCertBytes)
	require.NoError(t, err)

	require.NoError(t, leaf.CheckSignatureFrom(ca))
	require.NoError(t, ca.CheckSignatureFrom(root))
	assert.Error(t, leaf.CheckSignatureFrom(root), "leaf is not signed by the root")
}

// Certificates on other curves take the plain crypto/x509 path unchanged.
func TestParseCertificate_NonBrainpoolFallsThrough(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nist"},
		DNSNames:     []string{"nist.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := brainpool.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, []string{"nist.example"}, cert.DNSNames)
	assert.Equal(t, elliptic.P256(), cert.PublicKey.(*ecdsa.PublicKey).Curve)
}

func TestValidatePublicKey(t *testing.T) {
	key, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, brainpool.ValidatePublicKey(&key.PublicKey))

	p := brainpool.P256r1().Params().P
	for name, pub := range map[string]*ecdsa.PublicKey{
		"nil":          nil,
		"nil coords":   {Curve: brainpool.P256r1()},
		"off curve":    {Curve: brainpool.P256r1(), X: key.X, Y: new(big.Int).Add(key.Y, big.NewInt(1))},
		"out of range": {Curve: brainpool.P256r1(), X: new(big.Int).Add(key.X, p), Y: key.Y},
	} {
		assert.Error(t, brainpool.ValidatePublicKey(pub), name)
	}
}
