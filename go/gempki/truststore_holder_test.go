package gempki_test

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustStoreHolder_InitialAndSet(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	first, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	second, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)

	h := gempki.NewTrustStoreHolder(first)
	assert.Same(t, first, h.Current())

	require.NoError(t, h.Set(second))
	assert.Same(t, second, h.Current())
}

func TestTrustStoreHolder_RejectsNilSet(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	h := gempki.NewTrustStoreHolder(ts)
	err = h.Set(nil)
	require.Error(t, err)
	// Current store untouched.
	assert.Same(t, ts, h.Current())
}

func TestTrustStoreHolder_NilHolderSafe(t *testing.T) {
	t.Parallel()

	var h *gempki.TrustStoreHolder
	assert.Nil(t, h.Current())
	assert.Error(t, h.Set(nil))
	assert.Error(t, h.Reload(t.Context(), nil))
}

func TestTrustStoreHolder_ReloadInvokesLoader(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	initial, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	refreshed, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)

	h := gempki.NewTrustStoreHolder(initial)
	require.NoError(t, h.Reload(t.Context(), stubLoader{store: refreshed}))
	assert.Same(t, refreshed, h.Current())
}

func TestTrustStoreHolder_ReloadFailureKeepsCurrent(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	initial, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)

	h := gempki.NewTrustStoreHolder(initial)
	err = h.Reload(t.Context(), stubLoader{err: errors.New("boom")})
	require.Error(t, err)
	assert.Same(t, initial, h.Current(), "failed reload must not erase the current store")
}

func TestTrustStoreHolder_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	a, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	b, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})

	h := gempki.NewTrustStoreHolder(a)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			for range 1000 {
				_ = h.Current()
				if i&1 == 0 {
					_ = h.Set(a)
				} else {
					_ = h.Set(b)
				}
			}
		}(i)
	}
	wg.Wait()

	// After the storm, Current must be either a or b — not garbage.
	got := h.Current()
	assert.True(t, got == a || got == b)
}

func TestTrustStoreHolder_ReloadRejectsNilLoader(t *testing.T) {
	t.Parallel()
	h := gempki.NewTrustStoreHolder(nil)
	err := h.Reload(context.Background(), nil)
	require.Error(t, err)
}
