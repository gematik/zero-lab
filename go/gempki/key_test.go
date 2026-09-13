package gempki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyKey(t *testing.T) {
	t.Parallel()
	before := time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC)
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ec := func(c elliptic.Curve) crypto.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		require.NoError(t, err)
		return &k.PublicKey
	}
	rsaKey := func(bits int) crypto.PublicKey {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		return &k.PublicKey
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name string
		key  crypto.PublicKey
		at   time.Time
		want gempki.KeyStatus
		desc string
	}{
		{"brainpoolP256r1", ec(brainpool.P256r1()), after, gempki.KeyAdmissible, "ECDSA brainpoolP256r1"},
		{"P-256", ec(elliptic.P256()), after, gempki.KeyAdmissible, "ECDSA P-256"},
		{"P-224", ec(elliptic.P224()), after, gempki.KeyNotAdmissible, "ECDSA P-224"},
		{"P-384", ec(elliptic.P384()), after, gempki.KeyNotAdmissible, "ECDSA P-384"},
		{"P-521", ec(elliptic.P521()), after, gempki.KeyNotAdmissible, "ECDSA P-521"},
		{"brainpoolP384r1", ec(brainpool.P384r1()), after, gempki.KeyNotAdmissible, "ECDSA brainpoolP384r1"},
		{"RSA 1024", rsaKey(1024), before, gempki.KeyNotAdmissible, "RSA 1024"},
		{"RSA 2048 before end of 2025", rsaKey(2048), before, gempki.KeyAdmissible, "RSA 2048"},
		{"RSA 2048 after end of 2025", rsaKey(2048), after, gempki.KeyPhasedOut, "RSA 2048"},
		{"RSA 3072", rsaKey(3072), after, gempki.KeyAdmissible, "RSA 3072"},
		{"Ed25519", edPub, after, gempki.KeyNotAdmissible, "ed25519.PublicKey"},
		{"nil", nil, after, gempki.KeyNotAdmissible, "no public key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, desc := gempki.ClassifyKey(tc.key, tc.at)
			assert.Equal(t, tc.want, status, "status %s", status)
			assert.Equal(t, tc.desc, desc)
		})
	}
}

// issueWithKey mints an end entity under the test PKI's P-256 SubCA with
// whatever key the test hands in — testca itself only mints ECDSA on the
// TI curves, which is the point of this test.
func issueWithKey(t *testing.T, issuer *testca.Node, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "key-under-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, pub, issuer.Key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestValidator_KeyAdmissibility(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	validate := func(t *testing.T, ee *x509.Certificate, at time.Time) *gempki.ValidationResult {
		t.Helper()
		v := &gempki.Validator{
			TrustStore:     ts,
			RevocationMode: gempki.RevocationModeDisabled,
			TimeFunc:       func() time.Time { return at },
		}
		result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAKomp.Cert})
		require.NoError(t, err)
		return result
	}
	now := time.Now()

	t.Run("P-256 end entity is admissible", func(t *testing.T) {
		t.Parallel()
		result := validate(t, pki.EEZeta.Cert, now)
		assert.True(t, result.Valid, "%v", result.Errors)
		assert.Empty(t, result.Warnings)
	})
	t.Run("RSA 2048 is phased out after 2025", func(t *testing.T) {
		t.Parallel()
		ee := issueWithKey(t, pki.SubCAKomp, &rsa2048.PublicKey)
		result := validate(t, ee, now)
		assert.True(t, result.Valid, "%v", result.Errors)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, gempki.ErrCodeKeyPhasedOut, result.Warnings[0].Code)
		assert.Contains(t, result.Warnings[0].Message, "RSA 2048")
	})
	for name, pub := range map[string]crypto.PublicKey{
		"RSA 1024": &rsa1024.PublicKey,
		"P-224":    &p224.PublicKey,
		"Ed25519":  edPub,
	} {
		t.Run(name+" is rejected", func(t *testing.T) {
			t.Parallel()
			ee := issueWithKey(t, pki.SubCAKomp, pub)
			result := validate(t, ee, now)
			assert.False(t, result.Valid)
			assert.True(t, result.HasError(gempki.ErrCodeKeyNotAdmissible), "%v", result.Errors)
		})
	}
}
