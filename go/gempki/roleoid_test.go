package gempki_test

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRoleOIDExtractor_BrainpoolSMCBArztpraxis(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	oids, err := gempki.DefaultRoleOIDExtractor(cert)
	require.NoError(t, err)
	require.Len(t, oids, 1)
	assert.True(t, oids[0].Equal(gempki.OIDInstArztpraxis),
		"expected OIDInstArztpraxis (1.2.276.0.76.4.50), got %s", oids[0])
}

func TestDefaultRoleOIDExtractor_NoAdmissionExtensionReturnsEmpty(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	// EEZeta is a Komp cert without an Admission extension.
	oids, err := gempki.DefaultRoleOIDExtractor(pki.EEZeta.Cert)
	require.NoError(t, err)
	assert.Empty(t, oids)
}

func TestCheckRoleOID_PassWhenAllowedIntersects(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID(
		nil,
		gempki.OIDInstArztpraxis, // matches
		gempki.OIDInstKrankenhaus,
	)
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckRoleOID_FailWhenAllowedDoesNotIntersect(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID(nil, gempki.OIDInstKrankenhaus, gempki.OIDInstOeffentlicheApo)
	err := check(t.Context(), cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrRoleOIDMissing))
	assert.Contains(t, err.Error(), "1.2.276.0.76.4.50") // what the cert actually has
}

func TestCheckRoleOID_EmptyAllowedIsNoConstraint(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID(nil)
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckRoleOID_CustomExtractor(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// Stub extractor that always returns OIDProfArzt regardless of cert.
	extractor := func(_ *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
		return []asn1.ObjectIdentifier{gempki.OIDProfArzt}, nil
	}
	check := gempki.CheckRoleOID(extractor, gempki.OIDProfArzt)
	require.NoError(t, check(t.Context(), pki.EEZeta.Cert))
}

func TestCheckRoleOID_ExtractorErrorBecomesValidationError(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	extractor := func(_ *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
		return nil, errors.New("simulated extraction failure")
	}
	check := gempki.CheckRoleOID(extractor, gempki.OIDProfArzt)
	err = check(t.Context(), pki.EEZeta.Cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrRoleOIDMissing))
	assert.Contains(t, err.Error(), "simulated extraction failure")
}

// parseBrainpoolSMCBEE returns the SMC-B EE from the testdata fixtures.
// This cert carries the gematik Admission extension with OIDInstArztpraxis
// (1.2.276.0.76.4.50).
func parseBrainpoolSMCBEE(t *testing.T) *x509.Certificate {
	t.Helper()
	certs, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)
	require.Len(t, certs, 1)
	return certs[0]
}
