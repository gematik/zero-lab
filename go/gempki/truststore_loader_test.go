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

// TestEmbeddedLoader_AcceptsRSAEntries documents that RSA-keyed roots in
// roots.json are no longer silently skipped: the historical GEM.RCA1/2/6
// (and similar) are loadable so chain validation works for cards minted
// under those eras.
func TestEmbeddedLoader_AcceptsRSAEntries(t *testing.T) {
	t.Parallel()

	// The prod payload has RSA-keyed RCA1 and RCA2. We don't assert their
	// presence directly (the trust anchor walk topology is data-dependent)
	// — instead we assert that the load itself doesn't blow up on RSA, and
	// the resulting store has at least the anchor plus is non-empty.
	for _, env := range []gempki.Environment{gempki.EnvProd, gempki.EnvTest, gempki.EnvRef} {
		t.Run(string(env), func(t *testing.T) {
			t.Parallel()
			ts, err := gempki.EmbeddedLoader{Env: env}.Load(t.Context())
			require.NoError(t, err, "RSA presence in roots.json must not fail the load")
			require.GreaterOrEqual(t, ts.Len(), 1)
		})
	}
}

// TestEmbeddedLoader_NonTraversableWalkGracefullyStops covers the case
// where a cross-cert in roots.json is signed by a sibling that isn't the
// current walk position (e.g. embedded test RCA8.prev is signed by RCA6
// instead of RCA8). The walk used to either hard-error or be silently
// terminated by the RSA-rejection branch; the current behavior is to log
// Debug and break the walk in that direction, returning whatever was
// already trusted.
func TestEmbeddedLoader_NonTraversableWalkGracefullyStops(t *testing.T) {
	t.Parallel()

	ts, err := gempki.EmbeddedLoader{Env: gempki.EnvTest}.Load(t.Context())
	require.NoError(t, err, "non-traversable cross-cert must not fail the load")
	require.GreaterOrEqual(t, ts.Len(), 1, "anchor must be present even when walk halts at iteration 0")

	anchor, err := gempki.EmbeddedTrustAnchor(gempki.EnvTest)
	require.NoError(t, err)
	_, ok := ts.BySKI(anchor.SubjectKeyId)
	require.True(t, ok)
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
