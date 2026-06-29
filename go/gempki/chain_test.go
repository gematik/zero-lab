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

func TestBuildChain_BrainpoolHappyPath(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	chain, err := gempki.BuildChain(
		pki.EEArzt.Cert,
		[]*x509.Certificate{pki.SubCAHBA.Cert},
		ts,
		gempki.BuildChainOptions{},
	)
	require.NoError(t, err)
	require.Len(t, chain, 3, "EE → SubCA → Root")
	assert.Equal(t, pki.EEArzt.Cert.Subject.CommonName, chain[0].Subject.CommonName)
	assert.Equal(t, pki.SubCAHBA.Cert.Subject.CommonName, chain[1].Subject.CommonName)
	assert.Equal(t, pki.RCA1.Cert.Subject.CommonName, chain[2].Subject.CommonName)
}

func TestBuildChain_NISTHappyPath(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)

	chain, err := gempki.BuildChain(
		pki.EEZeta.Cert,
		[]*x509.Certificate{pki.SubCAKomp.Cert},
		ts,
		gempki.BuildChainOptions{},
	)
	require.NoError(t, err)
	require.Len(t, chain, 3)
}

func TestBuildChain_MixedCurveChain(t *testing.T) {
	t.Parallel()

	// RCA1 (brainpool) → SubCAMixed (brainpool) → EEMixed (NIST P-256).
	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	chain, err := gempki.BuildChain(
		pki.EEMixed.Cert,
		[]*x509.Certificate{pki.SubCAMixed.Cert},
		ts,
		gempki.BuildChainOptions{},
	)
	require.NoError(t, err)
	require.Len(t, chain, 3, "mixed-curve chain must still build")
}

func TestBuildChain_RogueRootNotInTrustStore(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	// Trust store only has RCA1; rogue chain anchors at RogueRoot.
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	_, err = gempki.BuildChain(
		pki.EERogue.Cert,
		nil,
		ts,
		gempki.BuildChainOptions{},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, gempki.ErrChainIncomplete)
}

func TestBuildChain_MissingIntermediate(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	// SubCAHBA is the missing link.
	_, err = gempki.BuildChain(
		pki.EEArzt.Cert,
		nil,
		ts,
		gempki.BuildChainOptions{},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, gempki.ErrChainIncomplete)
}

func TestBuildChain_RejectsNilInputs(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	_, err = gempki.BuildChain(nil, nil, ts, gempki.BuildChainOptions{})
	require.Error(t, err)

	_, err = gempki.BuildChain(pki.EEArzt.Cert, nil, nil, gempki.BuildChainOptions{})
	require.Error(t, err)
}

func TestBuildChain_RespectsMaxChainLen(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	// MaxChainLen=2 → only [EE, Root] allowed, but the real chain is 3 long.
	_, err = gempki.BuildChain(
		pki.EEArzt.Cert,
		[]*x509.Certificate{pki.SubCAHBA.Cert},
		ts,
		gempki.BuildChainOptions{MaxChainLen: 2},
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrChainIncomplete), "got %v", err)
}
