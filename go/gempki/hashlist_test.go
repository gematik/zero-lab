package gempki_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashListChecker_GoodWhenAbsent(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	c := gempki.NewHashListChecker()

	result, err := c.Check(t.Context(), pki.EEArzt.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusGood, result.Status)
	assert.Equal(t, gempki.RevocationSourceHashList, result.Source)
}

func TestHashListChecker_RevokedWhenPresent(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	c := gempki.NewHashListChecker()
	revokedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	c.Add(pki.EERevoked.Cert, gempki.HashListEntry{
		RevokedAt: revokedAt,
		Reason:    "keyCompromise",
	})

	result, err := c.Check(t.Context(), pki.EERevoked.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusRevoked, result.Status)
	assert.True(t, result.RevokedAt.Equal(revokedAt))
	assert.Equal(t, "keyCompromise", result.Reason)
}

func TestHashListChecker_LoadFromText(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	body := strings.Join([]string{
		"# comment line — must be skipped",
		"",
		gempki.HashCert(pki.EERevoked.Cert) + "  2026-06-01T00:00:00Z  superseded",
	}, "\n")

	c := gempki.NewHashListChecker()
	require.NoError(t, c.LoadFrom(strings.NewReader(body)))
	assert.Equal(t, 1, c.Len())

	result, err := c.Check(t.Context(), pki.EERevoked.Cert, pki.SubCAHBA.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusRevoked, result.Status)
	assert.Equal(t, "superseded", result.Reason)
}

func TestHashListChecker_LoadFromRejectsBadLines(t *testing.T) {
	t.Parallel()

	cases := []string{
		"deadbeef  not-a-timestamp",
		"notahex  2026-01-01T00:00:00Z",
		"singlefield",
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			c := gempki.NewHashListChecker()
			err := c.LoadFrom(strings.NewReader(bad))
			require.Error(t, err)
		})
	}
}

func TestHashListHolder_AtomicSwap(t *testing.T) {
	t.Parallel()

	a := gempki.NewHashListChecker()
	b := gempki.NewHashListChecker()
	h := gempki.NewHashListHolder(a)
	assert.Same(t, a, h.Current())
	require.NoError(t, h.Set(b))
	assert.Same(t, b, h.Current())
	require.Error(t, h.Set(nil))
}
