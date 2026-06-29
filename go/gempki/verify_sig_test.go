package gempki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCertificateSignature_BrainpoolChain(t *testing.T) {
	t.Parallel()

	root, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	require.Len(t, root, 1)

	ca, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBCA51PEM))
	require.NoError(t, err)
	require.Len(t, ca, 1)

	ee, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)
	require.Len(t, ee, 1)

	require.NoError(t, gempki.VerifyCertificateSignature(ca[0], root[0]),
		"intermediate must verify under root")
	require.NoError(t, gempki.VerifyCertificateSignature(ee[0], ca[0]),
		"EE must verify under intermediate")
}

func TestVerifyCertificateSignature_NISTChain(t *testing.T) {
	t.Parallel()

	// Generate a NIST P-256 root and a child cert signed by it.
	rootDER, rootKey := makeSelfSignedECDSA(t, elliptic.P256(), "nist-root")
	root, err := gempki.ParseCertificate(rootDER)
	require.NoError(t, err)

	childKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	childTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "nist-child"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	childDER, err := x509.CreateCertificate(rand.Reader, childTmpl, root, &childKey.PublicKey, rootKey)
	require.NoError(t, err)
	child, err := gempki.ParseCertificate(childDER)
	require.NoError(t, err)

	require.NoError(t, gempki.VerifyCertificateSignature(child, root))
}

func TestVerifyCertificateSignature_WrongIssuer(t *testing.T) {
	t.Parallel()

	root, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ee, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)

	// EE was signed by SMCB-CA5, not directly by RCA5.
	err = gempki.VerifyCertificateSignature(ee[0], root[0])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

// TestVerifyCertificateSignature_RSAParentMismatch covers an RSA parent with
// an ECDSA-signed child: the parent type is allowed, but stdlib's
// CheckSignatureFrom rejects the algorithm/key mismatch. The error must
// still be wrapped by gempki's "signature verification failed" prefix
// (no ErrRSANotSupported anymore — that sentinel is gone).
func TestVerifyCertificateSignature_RSAParentMismatch(t *testing.T) {
	t.Parallel()

	rsaDER := makeSelfSignedRSA(t, "rsa-parent")
	rsaCert, err := x509.ParseCertificate(rsaDER)
	require.NoError(t, err)

	child, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)

	err = gempki.VerifyCertificateSignature(child[0], rsaCert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyCertificateSignature_NilArgs(t *testing.T) {
	t.Parallel()

	root, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)

	require.Error(t, gempki.VerifyCertificateSignature(nil, root[0]))
	require.Error(t, gempki.VerifyCertificateSignature(root[0], nil))
}
