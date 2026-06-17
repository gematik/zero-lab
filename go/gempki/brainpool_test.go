package gempki_test

import (
	"crypto/elliptic"
	"encoding/asn1"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrainpoolCurveExports(t *testing.T) {
	t.Parallel()

	assert.Same(t, brainpool.P256r1(), gempki.BrainpoolP256r1(),
		"gempki.BrainpoolP256r1 must alias brainpool.P256r1")
	assert.Same(t, brainpool.P384r1(), gempki.BrainpoolP384r1(),
		"gempki.BrainpoolP384r1 must alias brainpool.P384r1")
}

func TestCurveForOID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		wantCurve elliptic.Curve
		wantErr   bool
	}{
		{"NIST_P256", gempki.OIDNISTP256, elliptic.P256(), false},
		{"NIST_P384", gempki.OIDNISTP384, elliptic.P384(), false},
		{"Brainpool_P256r1", gempki.OIDBrainpoolP256r1, brainpool.P256r1(), false},
		{"Brainpool_P384r1", gempki.OIDBrainpoolP384r1, brainpool.P384r1(), false},
		{"Brainpool_P512r1_unsupported", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, nil, true},
		{"NIST_P521_unsupported", asn1.ObjectIdentifier{1, 3, 132, 0, 35}, nil, true},
		{"junk_OID", asn1.ObjectIdentifier{1, 2, 3, 4}, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := gempki.CurveForOID(tc.oid)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Same(t, tc.wantCurve, got)
		})
	}
}
