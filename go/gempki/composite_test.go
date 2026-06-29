package gempki_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubChecker is a tiny RevocationChecker for tests.
type stubChecker struct {
	result *gempki.RevocationResult
	err    error
}

func (s stubChecker) Check(_ context.Context, _, _ *x509.Certificate) (*gempki.RevocationResult, error) {
	return s.result, s.err
}

func goodResult() *gempki.RevocationResult {
	return &gempki.RevocationResult{Status: gempki.RevocationStatusGood, Source: gempki.RevocationSourceOCSP}
}

func revokedResult() *gempki.RevocationResult {
	return &gempki.RevocationResult{Status: gempki.RevocationStatusRevoked, Source: gempki.RevocationSourceHashList, Reason: "test"}
}

func unknownResult() *gempki.RevocationResult {
	return &gempki.RevocationResult{Status: gempki.RevocationStatusUnknown, Source: gempki.RevocationSourceOCSP, Reason: "no answer"}
}

func TestCompositeChecker_PriorityFirstDefinitiveWins(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackPriority,
		Checkers: []gempki.RevocationChecker{
			stubChecker{result: unknownResult()},
			stubChecker{result: revokedResult()},
			stubChecker{result: goodResult()},
		},
	}
	r, err := cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusRevoked, r.Status, "first definitive (Revoked) wins")
}

func TestCompositeChecker_PriorityAllUnknownYieldsUnknown(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackPriority,
		Checkers: []gempki.RevocationChecker{
			stubChecker{result: unknownResult()},
			stubChecker{result: unknownResult()},
		},
	}
	r, err := cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, r.Status)
}

func TestCompositeChecker_PriorityAllErrorYieldsError(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackPriority,
		Checkers: []gempki.RevocationChecker{
			stubChecker{err: errors.New("a down")},
			stubChecker{err: errors.New("b down")},
		},
	}
	_, err = cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a down")
	assert.Contains(t, err.Error(), "b down")
}

func TestCompositeChecker_AllAgreeConsensus(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackAllAgree,
		Checkers: []gempki.RevocationChecker{
			stubChecker{result: goodResult()},
			stubChecker{result: goodResult()},
		},
	}
	r, err := cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusGood, r.Status)
}

func TestCompositeChecker_AllAgreeDisagreementYieldsUnknown(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackAllAgree,
		Checkers: []gempki.RevocationChecker{
			stubChecker{result: goodResult()},
			stubChecker{result: revokedResult()},
		},
	}
	r, err := cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, r.Status)
	assert.Contains(t, r.Reason, "disagreement")
}

func TestCompositeChecker_AllAgreeUnknownVoidsConsensus(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	cc := gempki.CompositeChecker{
		Order: gempki.FallbackAllAgree,
		Checkers: []gempki.RevocationChecker{
			stubChecker{result: goodResult()},
			stubChecker{result: unknownResult()},
		},
	}
	r, err := cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, r.Status)
}

func TestCompositeChecker_EmptyIsError(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cc := gempki.CompositeChecker{}
	_, err = cc.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.Error(t, err)
}
