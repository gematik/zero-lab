package gempki_test

import (
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedTSLSignerAnchor_KnownCommonNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		env    gempki.Environment
		wantCN string
	}{
		{gempki.EnvProd, "GEM.TSL-CA3"},
		{gempki.EnvTest, "GEM.TSL-CA28 TEST-ONLY"},
		{gempki.EnvDev, "GEM.TSL-CA28 TEST-ONLY"},
		{gempki.EnvRef, "GEM.TSL-CA28 TEST-ONLY"},
	}
	for _, tc := range cases {
		t.Run(string(tc.env), func(t *testing.T) {
			t.Parallel()
			cert, err := gempki.EmbeddedTSLSignerAnchor(tc.env)
			require.NoError(t, err)
			require.NotNil(t, cert)
			assert.Equal(t, tc.wantCN, cert.Subject.CommonName)
			// Sanity: every TSL-Signer-CA is itself issued by a GEM.RCA.
			assert.Contains(t, cert.Issuer.CommonName, "GEM.RCA",
				"TSL-Signer-CA is structurally a SubCA under GEM.RCA<n>; "+
					"if this changes we want to know")
		})
	}
}

func TestEmbeddedTSLSignerAnchor_UnknownEnv(t *testing.T) {
	t.Parallel()
	_, err := gempki.EmbeddedTSLSignerAnchor(gempki.Environment("bogus"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no embedded TSL-Signer-CA anchor")
}

func TestEmbeddedTSLSignerLoader_ReturnsTrustStoreWithAnchor(t *testing.T) {
	t.Parallel()

	loader := gempki.EmbeddedTSLSignerLoader{Env: gempki.EnvProd}
	ts, err := loader.Load(t.Context())
	require.NoError(t, err)
	require.NotNil(t, ts)
	assert.Equal(t, 1, ts.Len(), "single TSL-Signer-CA today (cross-cert walk lands when there's a sibling)")

	// The anchor must be retrievable via both index paths.
	anchor, err := gempki.EmbeddedTSLSignerAnchor(gempki.EnvProd)
	require.NoError(t, err)

	bySKI, ok := ts.BySKI(anchor.SubjectKeyId)
	require.True(t, ok)
	assert.True(t, bySKI.Equal(anchor))

	byCN, ok := ts.ByCommonName(anchor.Subject.CommonName)
	require.True(t, ok)
	assert.True(t, byCN.Equal(anchor))
}

func TestEmbeddedTSLSignerAnchor_Memoised(t *testing.T) {
	t.Parallel()
	a, err := gempki.EmbeddedTSLSignerAnchor(gempki.EnvProd)
	require.NoError(t, err)
	b, err := gempki.EmbeddedTSLSignerAnchor(gempki.EnvProd)
	require.NoError(t, err)
	assert.Same(t, a, b, "TSL anchor parse must memoise — repeated calls return the same *Certificate")
}

func TestEmbeddedTSLSignerAnchor_DistinctFromKomponentenAnchor(t *testing.T) {
	t.Parallel()

	// Sanity: the TSL-Signer-CA and the Komponenten-PKI anchor must NOT be
	// the same cert. If they ever are, the strategy / data are confused.
	for _, env := range []gempki.Environment{gempki.EnvProd, gempki.EnvTest} {
		tslAnchor, err := gempki.EmbeddedTSLSignerAnchor(env)
		require.NoError(t, err)
		ti, err := gempki.EmbeddedTrustAnchor(env)
		require.NoError(t, err)
		assert.False(t, tslAnchor.Equal(ti),
			"%s: TSL-Signer-CA and Komponenten-PKI anchor must be different certs", env)
		assert.True(t, strings.Contains(tslAnchor.Subject.CommonName, "TSL-CA"),
			"%s: TSL anchor CN must contain TSL-CA, got %q", env, tslAnchor.Subject.CommonName)
		assert.True(t, strings.Contains(ti.Subject.CommonName, "RCA"),
			"%s: Komponenten-PKI anchor CN must contain RCA, got %q", env, ti.Subject.CommonName)
	}
}
