package gempki_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildChain is a small helper that runs BuildChain on testca fixtures and
// fatals on error, returning the result.
func buildChainHelper(t *testing.T, leaf *x509.Certificate, mids []*x509.Certificate, ts *gempki.TrustStore) []*x509.Certificate {
	t.Helper()
	chain, err := gempki.BuildChain(leaf, mids, ts, gempki.BuildChainOptions{})
	require.NoError(t, err)
	return chain
}

func TestValidatePath_BrainpoolHappyPath(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEArzt.Cert, []*x509.Certificate{pki.SubCAHBA.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
	require.Len(t, result.Positions, 3)
	assert.Equal(t, gempki.PositionEE, result.Positions[0])
	assert.Equal(t, gempki.PositionSubCA, result.Positions[1])
	assert.Equal(t, gempki.PositionRoot, result.Positions[2])
}

func TestValidatePath_NISTHappyPath(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEZeta.Cert, []*x509.Certificate{pki.SubCAKomp.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidatePath_MixedCurveChainValidates(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEMixed.Cert, []*x509.Certificate{pki.SubCAMixed.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.True(t, result.Valid, "cross-curve chain failed: %v", result.Errors)
}

func TestValidatePath_ExpiredEERejected(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEExpired.Cert, []*x509.Certificate{pki.SubCAHBA.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeExpired), "errors: %v", result.Errors)
}

func TestValidatePath_NotYetValidRejected(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EENotYetValid.Cert, []*x509.Certificate{pki.SubCAHBA.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeNotYetValid))
}

func TestValidatePath_ExpiredSubCAFlagsParentNotEE(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEUnderExpired.Cert, []*x509.Certificate{pki.SubCAExpired.Cert}, ts)

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	// Exactly one cert (the SubCA) is expired; the EE itself has valid dates.
	var expiredCount int
	for _, e := range result.Errors {
		if e.Code == gempki.ErrCodeExpired {
			expiredCount++
			assert.Contains(t, e.Subject, "Expired", "expected Expired SubCA, got %q", e.Subject)
		}
	}
	assert.Equal(t, 1, expiredCount)
}

func TestValidatePath_TimeFuncFlipsValidity(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	chain := buildChainHelper(t, pki.EEArzt.Cert, []*x509.Certificate{pki.SubCAHBA.Cert}, ts)

	// Fixtures are all valid for ~5 years from now; jumping 20 years forward
	// must make every cert expired and turn a happy-path chain into a failure
	// — demonstrating TimeFunc is plumbed end-to-end.
	future := time.Now().Add(20 * 365 * 24 * time.Hour)
	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{
		TimeFunc: func() time.Time { return future },
	})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeExpired))
}

// TestValidatePath_RSACertSignatureMismatch shows that an RSA cert spliced
// into a chain no longer triggers a categorical RSA rejection (that policy
// is gone), but the cryptographic signature check still fails because the
// adjacent links weren't actually issued by an RSA key. The chain is
// invalid; the failure surfaces as ErrCodeSignatureInvalid.
func TestValidatePath_RSACertSignatureMismatch(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	rsaDER := makeSelfSignedRSA(t, "rogue-rsa-subca")
	rsaCert, err := x509.ParseCertificate(rsaDER)
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, rsaCert, pki.RCA1.Cert}

	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeSignatureInvalid),
		"RSA cert spliced into ECC chain must fail signature verification, got %v", result.Errors)
}

func TestValidatePath_WrongIssuer(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// Hand-build a chain that *looks* connected but isn't: EE signed by
	// SubCAHBA, then claim SubCAKomp (NIST) is its parent. Signature
	// verification at link 1→2 must fail.
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAKomp.Cert, pki.RCA7.Cert}
	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeSignatureInvalid))
}

func TestValidatePath_RequiresMinimumChain(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	_, err = gempki.ValidatePath(t.Context(), []*x509.Certificate{pki.EEArzt.Cert}, gempki.ValidatePathOptions{})
	require.Error(t, err, "single-cert chain must be rejected")
}
