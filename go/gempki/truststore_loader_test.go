package gempki_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedLoader_AllEnvironments(t *testing.T) {
	t.Parallel()

	cases := []gempki.Environment{
		gempki.EnvTest,
		gempki.EnvRef,
		gempki.EnvDev,
		gempki.EnvProd,
	}
	for _, env := range cases {
		t.Run(string(env), func(t *testing.T) {
			t.Parallel()
			loader := gempki.EmbeddedLoader{Env: env}
			ts, err := loader.Load(t.Context())
			require.NoError(t, err)
			require.NotNil(t, ts)
			assert.GreaterOrEqual(t, ts.Len(), 1, "%s must produce at least one root", env)

			// The anchor must be present in the resulting TrustStore.
			anchor, err := gempki.EmbeddedTrustAnchor(env)
			require.NoError(t, err)
			_, ok := ts.BySKI(anchor.SubjectKeyId)
			assert.True(t, ok, "trust anchor must end up in the store")
		})
	}
}

func TestEmbeddedLoader_UnknownEnvironmentFails(t *testing.T) {
	t.Parallel()
	loader := gempki.EmbeddedLoader{Env: gempki.Environment("bogus")}
	_, err := loader.Load(t.Context())
	require.Error(t, err)
}

func TestCompositeLoader_FirstSuccessWins(t *testing.T) {
	t.Parallel()

	working := gempki.EmbeddedLoader{Env: gempki.EnvRef}
	broken := stubLoader{err: errors.New("simulated network down")}

	composite := gempki.CompositeLoader{
		Loaders: []gempki.Loader{broken, working},
	}
	ts, err := composite.Load(t.Context())
	require.NoError(t, err)
	require.NotNil(t, ts)
	assert.Positive(t, ts.Len())
}

func TestCompositeLoader_AllFail(t *testing.T) {
	t.Parallel()

	a := stubLoader{err: errors.New("a failed")}
	b := stubLoader{err: errors.New("b failed")}
	composite := gempki.CompositeLoader{Loaders: []gempki.Loader{a, b}}

	_, err := composite.Load(t.Context())
	require.Error(t, err)
	// Both errors must be present in the joined error.
	assert.Contains(t, err.Error(), "a failed")
	assert.Contains(t, err.Error(), "b failed")
}

func TestCompositeLoader_EmptyIsError(t *testing.T) {
	t.Parallel()
	_, err := gempki.CompositeLoader{}.Load(t.Context())
	require.Error(t, err)
}

func TestEmbeddedTrustAnchor_Memoised(t *testing.T) {
	t.Parallel()

	a, err := gempki.EmbeddedTrustAnchor(gempki.EnvRef)
	require.NoError(t, err)
	b, err := gempki.EmbeddedTrustAnchor(gempki.EnvRef)
	require.NoError(t, err)
	assert.Same(t, a, b, "trust anchor must be cached across calls")
}

type stubLoader struct {
	store *gempki.TrustStore
	err   error
}

func (s stubLoader) Load(_ context.Context) (*gempki.TrustStore, error) {
	return s.store, s.err
}
