package gempki

import (
	"errors"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The A_28419 walk is internal to root loading; these tests pin its steps
// directly so a regression names the step that broke.

func TestVerifyCrossSigned_HappyPath(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	// CrossCertRCA1ForRCA7: subject = RCA7's identity, signed by RCA1. All
	// seven steps hold for RCA7 as the subordinate.
	require.NoError(t, verifyCrossSignedAt(pki.RCA1.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert, time.Now()))
}

func TestVerifyCrossSigned_BadAnchorFailsStep1(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	err = verifyCrossSignedAt(pki.RogueRoot.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert, time.Now())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errCrossCert))
	assert.Contains(t, err.Error(), "step 1")
}

func TestVerifyCrossSigned_SKIMismatchFailsStep4(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	// SubCAHBA has a different SKI from RCA7, for which the cross cert was issued.
	err = verifyCrossSignedAt(pki.RCA1.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.SubCAHBA.Cert, time.Now())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errCrossCert))
	assert.Contains(t, err.Error(), "step 4")
}

func TestVerifyCrossSigned_ExpiredCrossFailsStep2(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	err = verifyCrossSignedAt(pki.RCA1.Cert, pki.CrossCertRCA1ForRCA7.Cert, pki.RCA7.Cert,
		pki.CrossCertRCA1ForRCA7.Cert.NotAfter.Add(time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step 2")
}
