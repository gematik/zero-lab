package gempki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCertificate_BrainpoolFixture(t *testing.T) {
	t.Parallel()

	der := fixtureBrainpoolEEDER(t)
	cert, err := gempki.ParseCertificate(der)
	require.NoError(t, err)

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key, got %T", cert.PublicKey)
	assert.Same(t, brainpool.P256r1(), pub.Curve, "brainpool curve must be set on parsed key")
	assert.Contains(t, cert.Subject.CommonName, "Arztpraxis")
}

func TestParseCertificate_NISTP256(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	cert, err := gempki.ParseCertificate(pki.RCA7.DER) // NIST P-256 root
	require.NoError(t, err)

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Same(t, elliptic.P256(), pub.Curve)
}

// TestParseCertificate_RSAAccepted documents that gempki now accepts RSA
// certificates. The historical TI roots (GEM.RCA1/2/6) are RSA-keyed and
// must be loadable for full chain validation; the older ECC-only policy
// is gone.
func TestParseCertificate_RSAAccepted(t *testing.T) {
	t.Parallel()

	cert, err := gempki.ParseCertificate(fixtureRSARoot(t).Raw)
	require.NoError(t, err)
	assert.Equal(t, "GEM.RCA2 TEST-ONLY", cert.Subject.CommonName)
	assert.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)
}

// TestParseCertificate_P521Accepted pins the post-policy-removal behavior:
// with assertECC gone, any curve the brainpool/stdlib parsers handle is
// accepted at parse time. Trust is gated by anchor membership in
// [gempki.TrustStore], not by parse-time key-type filtering.
func TestParseCertificate_P521Accepted(t *testing.T) {
	t.Parallel()

	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-p521"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)

	cert, err := gempki.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, "test-p521", cert.Subject.CommonName)
}

func TestParsePEMCertificates(t *testing.T) {
	t.Parallel()

	combined := []byte(fixtureBrainpoolRCA5PEM + "\n" + fixtureBrainpoolSMCBCA51PEM)
	certs, err := gempki.ParsePEMCertificates(combined)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.Contains(t, certs[0].Subject.CommonName, "RCA5")
	assert.Contains(t, certs[1].Subject.CommonName, "SMCB-CA51")
}

func TestParsePEMCertificates_SkipsNonCertBlocks(t *testing.T) {
	t.Parallel()

	keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0x01, 0x02}}
	combined := append(pem.EncodeToMemory(keyBlock), []byte(fixtureBrainpoolRCA5PEM)...)

	certs, err := gempki.ParsePEMCertificates(combined)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Contains(t, certs[0].Subject.CommonName, "RCA5")
}

func TestParsePEMCertificates_EmptyInput(t *testing.T) {
	t.Parallel()

	certs, err := gempki.ParsePEMCertificates(nil)
	require.NoError(t, err)
	assert.Empty(t, certs)
}
