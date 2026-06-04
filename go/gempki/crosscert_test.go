package gempki_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCrossSignedRoot_HappyPath(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// pki.CrossCertRCA1ForRCA7: subject=RCA7 identity, signed by RCA1.
	// The subordinate is RCA7 itself.
	//
	// Step 1 — passes (cross signed by RCA1).
	// Step 2 — passes (cross dated now..now+10y).
	// Step 3 — passes ("GEM.RCA7 TEST-ONLY" matches GEM.RCA\d+).
	// Step 4 — passes (cross SKI == subordinate SKI; both derived from RCA7 pubkey).
	// Step 5 — passes (same CN).
	// Step 6 — passes (same pubkey).
	// Step 7 — passes (RCA7 self-signature verifies under cross's pubkey == RCA7 pubkey).
	require.NoError(t,
		gempki.VerifyCrossSignedRoot(pki.RCA1.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert))
}

func TestVerifyCrossSignedRoot_BadAnchorFailsStep1(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// RogueRoot did not sign the cross cert.
	err = gempki.VerifyCrossSignedRoot(pki.RogueRoot.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert)
	require.Error(t, err)
	assert.ErrorIs(t, err, gempki.ErrCrossCertStep1)
}

func TestVerifyCrossSignedRoot_SKIMismatchFailsStep4(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// Use SubCAHBA (issued under RCA1, different SKI than RCA7) as the
	// subordinate. The cross cert was issued for RCA7, so SKI won't match.
	err = gempki.VerifyCrossSignedRoot(pki.RCA1.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.SubCAHBA.Cert)
	require.Error(t, err)
	assert.ErrorIs(t, err, gempki.ErrCrossCertStep4)
}

func TestVerifyCrossSignedRoot_RSAAnchorRejected(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	rsaDER := makeSelfSignedRSA(t, "rsa-anchor")
	rsaCert, err := x509.ParseCertificate(rsaDER)
	require.NoError(t, err)

	err = gempki.VerifyCrossSignedRoot(rsaCert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert)
	require.Error(t, err)
	// Step 1 wraps the assertECC error from VerifyCertificateSignature.
	assert.True(t,
		errors.Is(err, gempki.ErrCrossCertStep1) || errors.Is(err, gempki.ErrRSANotSupported),
		"got %v", err)
}
