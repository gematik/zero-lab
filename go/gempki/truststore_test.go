package gempki_test

import (
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTrustStore_DedupAndLookup(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// Pass RCA1 twice — dedupe should drop the second copy.
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert, pki.RCA7.Cert, pki.RCA1.Cert})
	require.NoError(t, err)
	assert.Equal(t, 2, ts.Len(), "duplicate SKI must dedupe")

	t.Run("ByCommonName", func(t *testing.T) {
		c, ok := ts.ByCommonName(pki.RCA1.Cert.Subject.CommonName)
		require.True(t, ok)
		assert.Equal(t, pki.RCA1.Cert.SerialNumber, c.SerialNumber)
	})

	t.Run("BySKI", func(t *testing.T) {
		c, ok := ts.BySKI(pki.RCA7.Cert.SubjectKeyId)
		require.True(t, ok)
		assert.Equal(t, pki.RCA7.Cert.SerialNumber, c.SerialNumber)
	})

	t.Run("CertPool", func(t *testing.T) {
		pool := ts.CertPool()
		require.NotNil(t, pool)
		// CertPool is opaque; the best we can do is confirm a chain we expect
		// to verify actually verifies.
		_, err := pki.SubCAHBA.Cert.Verify(x509.VerifyOptions{Roots: pool})
		require.NoError(t, err, "SubCAHBA must verify under TrustStore pool")
	})

	t.Run("Roots_returns_copy", func(t *testing.T) {
		r := ts.Roots()
		require.Len(t, r, 2)
		r[0] = nil
		// Mutating the returned slice must not affect the store.
		assert.Equal(t, 2, ts.Len())
	})
}

func TestNewTrustStore_RejectsRSA(t *testing.T) {
	t.Parallel()

	rsaDER := makeSelfSignedRSA(t, "rsa-root")
	// Parse with stdlib so we can sneak it past gempki.ParseCertificate.
	rsaCert, err := x509.ParseCertificate(rsaDER)
	require.NoError(t, err)

	_, err = gempki.NewTrustStore([]*x509.Certificate{rsaCert})
	require.Error(t, err)
	assert.ErrorIs(t, err, gempki.ErrRSANotSupported)
}

func TestNewTrustStore_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := gempki.NewTrustStore([]*x509.Certificate{nil})
	require.Error(t, err)
}

func TestTrustStore_NilReceiverSafe(t *testing.T) {
	t.Parallel()

	var ts *gempki.TrustStore
	assert.Nil(t, ts.Roots())
	c, ok := ts.ByCommonName("anything")
	assert.False(t, ok)
	assert.Nil(t, c)
	c2, ok := ts.BySKI([]byte("anything"))
	assert.False(t, ok)
	assert.Nil(t, c2)
	assert.Equal(t, 0, ts.Len())
	assert.NotNil(t, ts.CertPool(), "CertPool must return empty pool, not nil")
}

func TestNewTrustStore_SkiLookupIsHexNormalised(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	// Round-trip the SKI through hex and back — lookup must match.
	hexSKI := hex.EncodeToString(pki.RCA1.Cert.SubjectKeyId)
	raw, err := hex.DecodeString(hexSKI)
	require.NoError(t, err)
	_, ok := ts.BySKI(raw)
	assert.True(t, ok)
}
