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

func TestEvaluateChain_DisabledShortCircuits(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}
	out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode: gempki.RevocationModeDisabled,
	})
	require.NoError(t, err)
	assert.Empty(t, out.Errors)
	assert.Empty(t, out.Warnings)
}

func TestEvaluateChain_HappyPath_EEOnly(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	c := gempki.NewHashListChecker() // empty → reports Good for everything
	out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode:     gempki.RevocationModeHardFail,
		Checkers: []gempki.RevocationChecker{c},
	})
	require.NoError(t, err)
	assert.Empty(t, out.Errors)
	require.Len(t, out.PerCert, 3)
	require.NotNil(t, out.PerCert[0])
	assert.Equal(t, gempki.RevocationStatusGood, out.PerCert[0].Status)
	assert.Nil(t, out.PerCert[1], "SubCA skipped when CheckSubCAs=false")
}

func TestEvaluateChain_RevokedEEFailsHard(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EERevoked.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	c := gempki.NewHashListChecker()
	c.Add(pki.EERevoked.Cert, gempki.HashListEntry{
		RevokedAt: time.Now().Add(-time.Hour),
		Reason:    "test-keyCompromise",
	})

	out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode:     gempki.RevocationModeHardFail,
		Checkers: []gempki.RevocationChecker{c},
	})
	require.NoError(t, err)
	require.Len(t, out.Errors, 1)
	assert.Equal(t, gempki.ErrCodeRevoked, out.Errors[0].Code)
	assert.Equal(t, pki.EERevoked.Cert.Subject.CommonName, out.Errors[0].Subject)
}

func TestEvaluateChain_RevokedAlwaysFailsRegardlessOfMode(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EERevoked.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	c := gempki.NewHashListChecker()
	c.Add(pki.EERevoked.Cert, gempki.HashListEntry{RevokedAt: time.Now().Add(-time.Hour)})

	for _, mode := range []gempki.RevocationMode{
		gempki.RevocationModeHardFail,
		gempki.RevocationModeSoftFail,
		gempki.RevocationModeBestEffort,
	} {
		out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
			Mode:     mode,
			Checkers: []gempki.RevocationChecker{c},
		})
		require.NoError(t, err)
		assert.Len(t, out.Errors, 1, "mode %d should still hard-fail on Revoked", mode)
	}
}

func TestEvaluateChain_UnknownHardFailVsSoftFail(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	unknownChecker := stubChecker{result: unknownResult()}

	t.Run("hard_fail_rejects", func(t *testing.T) {
		t.Parallel()
		out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
			Mode:     gempki.RevocationModeHardFail,
			Checkers: []gempki.RevocationChecker{unknownChecker},
		})
		require.NoError(t, err)
		assert.Len(t, out.Errors, 1)
		assert.Equal(t, gempki.ErrCodeOCSPUnavailable, out.Errors[0].Code)
	})

	t.Run("soft_fail_warns", func(t *testing.T) {
		t.Parallel()
		out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
			Mode:     gempki.RevocationModeSoftFail,
			Checkers: []gempki.RevocationChecker{unknownChecker},
		})
		require.NoError(t, err)
		assert.Empty(t, out.Errors)
		assert.Len(t, out.Warnings, 1)
	})
}

func TestEvaluateChain_CacheHitSkipsChecker(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	preload := &gempki.RevocationResult{
		Status:    gempki.RevocationStatusGood,
		Source:    gempki.RevocationSourceCache,
		CheckedAt: time.Now(),
	}
	cache := gempki.NewInMemoryCache(10)
	require.NoError(t, cache.Put(t.Context(),
		gempki.RevocationCacheKey(pki.EEArzt.Cert), preload, time.Hour))

	// The checker errors so we can detect whether it was invoked.
	misuse := stubChecker{result: nil}

	out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode:     gempki.RevocationModeHardFail,
		Checkers: []gempki.RevocationChecker{misuse},
		Cache:    cache,
	})
	require.NoError(t, err)
	assert.Empty(t, out.Errors, "cache hit must short-circuit the checker")
	assert.Equal(t, gempki.RevocationStatusGood, out.PerCert[0].Status)
}

func TestEvaluateChain_CheckSubCAsIncludesIntermediates(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	c := gempki.NewHashListChecker()
	c.Add(pki.SubCAHBA.Cert, gempki.HashListEntry{RevokedAt: time.Now().Add(-time.Hour), Reason: "subca-bad"})

	out, err := gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode:        gempki.RevocationModeHardFail,
		Checkers:    []gempki.RevocationChecker{c},
		CheckSubCAs: true,
	})
	require.NoError(t, err)
	require.Len(t, out.Errors, 1)
	assert.Equal(t, gempki.ErrCodeRevoked, out.Errors[0].Code)
	assert.Equal(t, pki.SubCAHBA.Cert.Subject.CommonName, out.Errors[0].Subject)
}

func TestEvaluateChain_NoCheckersIsError(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	chain := []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert, pki.RCA1.Cert}

	_, err = gempki.EvaluateChain(t.Context(), chain, gempki.RevocationPolicy{
		Mode: gempki.RevocationModeHardFail,
	})
	require.Error(t, err)
}
