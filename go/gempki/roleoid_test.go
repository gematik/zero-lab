package gempki_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRoleOID_ReadsAdmissionExtension(t *testing.T) {
	t.Parallel()

	// The fixture SMC-B carries OIDInstArztpraxis (1.2.276.0.76.4.50) and
	// nothing else.
	cert := parseBrainpoolSMCBEE(t)
	require.NoError(t, gempki.CheckRoleOID(oid.InstArztpraxis)(t.Context(), cert))
	require.Error(t, gempki.CheckRoleOID(oid.InstKrankenhaus)(t.Context(), cert))
}

func TestCheckRoleOID_NoAdmissionExtensionAssertsNoRoles(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	// EEZeta is a Komp cert without an Admission extension: no roles, which
	// is fine when none are required and a failure when one is.
	require.NoError(t, gempki.CheckRoleOID()(t.Context(), pki.EEZeta.Cert))
	err = gempki.CheckRoleOID(oid.ProfArzt)(t.Context(), pki.EEZeta.Cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, &gempki.ValidationError{Code: gempki.ErrCodeRoleOIDMissing}))
}

func TestCheckRoleOID_PassWhenAllowedIntersects(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID(
		oid.InstArztpraxis, // matches
		oid.InstKrankenhaus,
	)
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckRoleOID_FailWhenAllowedDoesNotIntersect(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID(oid.InstKrankenhaus, oid.InstOeffentlicheApo)
	err := check(t.Context(), cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, &gempki.ValidationError{Code: gempki.ErrCodeRoleOIDMissing}))
	assert.Contains(t, err.Error(), "1.2.276.0.76.4.50") // what the cert actually has
}

func TestCheckRoleOID_EmptyAllowedIsNoConstraint(t *testing.T) {
	t.Parallel()

	cert := parseBrainpoolSMCBEE(t)
	check := gempki.CheckRoleOID()
	require.NoError(t, check(t.Context(), cert))
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
