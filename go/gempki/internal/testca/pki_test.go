package testca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_GeneratesPKIAndChainsVerify(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	t.Run("brainpool_chain_RCA1_SubHBA_EEArzt", func(t *testing.T) {
		require.NoError(t, pki.SubCAHBA.Cert.CheckSignatureFrom(pki.RCA1.Cert))
		require.NoError(t, pki.EEArzt.Cert.CheckSignatureFrom(pki.SubCAHBA.Cert))
	})

	t.Run("nist_chain_RCA7_SubKomp_EEZeta", func(t *testing.T) {
		require.NoError(t, pki.SubCAKomp.Cert.CheckSignatureFrom(pki.RCA7.Cert))
		require.NoError(t, pki.EEZeta.Cert.CheckSignatureFrom(pki.SubCAKomp.Cert))
	})

	t.Run("mixed_curve_chain_brainpool_root_NIST_leaf", func(t *testing.T) {
		require.NoError(t, pki.SubCAMixed.Cert.CheckSignatureFrom(pki.RCA1.Cert))
		require.NoError(t, pki.EEMixed.Cert.CheckSignatureFrom(pki.SubCAMixed.Cert))
		// EEMixed is NIST P-256 even though SubCAMixed is brainpool.
		pub, ok := pki.EEMixed.Cert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Same(t, elliptic.P256(), pub.Curve)
		subPub, ok := pki.SubCAMixed.Cert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Same(t, brainpool.P256r1(), subPub.Curve)
	})

	t.Run("cross_signed_RCA7_under_RCA1", func(t *testing.T) {
		// CrossCert says "I am RCA7's public key, signed by RCA1".
		require.NoError(t, pki.CrossCertRCA1ForRCA7.Cert.CheckSignatureFrom(pki.RCA1.Cert),
			"cross cert must verify under RCA1 (brainpool)")
		assert.Equal(t, pki.RCA7.Cert.Subject.CommonName,
			pki.CrossCertRCA1ForRCA7.Cert.Subject.CommonName,
			"cross cert subject must match RCA7's subject")
	})

	t.Run("rogue_root_does_not_verify_under_any_GEM_root", func(t *testing.T) {
		err := pki.EERogue.Cert.CheckSignatureFrom(pki.RCA1.Cert)
		require.Error(t, err, "rogue EE must not chain to GEM root")
	})
}

func TestNew_AdmissionExtensionIsParseable(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// Find the Admission extension on EEArzt by OID.
	var found bool
	for _, ext := range pki.EEArzt.Cert.Extensions {
		if ext.Id.String() == "1.3.36.8.3.3" {
			found = true
			assert.NotEmpty(t, ext.Value)
		}
	}
	assert.True(t, found, "EEArzt must carry the Admission extension (OID 1.3.36.8.3.3)")
}

func TestNew_KeysHaveCorrectCurves(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	cases := []struct {
		name      string
		node      func() *testca.Node
		wantCurve elliptic.Curve
	}{
		{"RCA1", func() *testca.Node { return pki.RCA1 }, brainpool.P256r1()},
		{"SubCAHBA", func() *testca.Node { return pki.SubCAHBA }, brainpool.P256r1()},
		{"EEArzt", func() *testca.Node { return pki.EEArzt }, brainpool.P256r1()},
		{"RCA7", func() *testca.Node { return pki.RCA7 }, elliptic.P256()},
		{"SubCAKomp", func() *testca.Node { return pki.SubCAKomp }, elliptic.P256()},
		{"EEZeta", func() *testca.Node { return pki.EEZeta }, elliptic.P256()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, ok := tc.node().Cert.PublicKey.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Same(t, tc.wantCurve, pub.Curve, "curve mismatch on %s", tc.name)
		})
	}
}
